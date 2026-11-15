"""Modell-Schnittstelle.

Hier ist die Stelle, an der das Basis-Modell gegen ein eigenes Modell
ausgetauscht wird. Beide Klassen haben eine ``predict(...)``-Methode, die
eine Wahrscheinlichkeit in [0, 1] liefert. Die API (``main.py``) kennt nur
diese Schnittstelle, nicht die Modell-Interna.

- ``UrlModel``  : scikit-learn-Pipeline (Char-N-Gramm-TF-IDF + lexikalische
                  Merkmale → Logistische Regression), trainiert mit
                  ``train/train_url_model.py``.
- ``TextModel`` : Platzhalter, delegiert an die Regeln in ``heuristics.py``.
                  Eigenes Textmodell hier einhängen (siehe README).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

import joblib
import numpy as np

from . import features as F
from .heuristics import TextVerdict, score_text

MODEL_DIR = Path(os.environ.get("PG_MODEL_DIR", Path(__file__).resolve().parent.parent / "models"))
URL_MODEL_PATH = MODEL_DIR / "url_model.joblib"


class SupportsUrlPredict(Protocol):
    def predict(self, urls: list[str]) -> list[float]: ...


class UrlModel:
    """Lädt die trainierte Pipeline und bewertet URLs."""

    def __init__(self, path: Path = URL_MODEL_PATH) -> None:
        if not path.exists():
            raise FileNotFoundError(
                f"Kein Modell unter {path}. Erst `python -m train.train_url_model` ausführen."
            )
        bundle = joblib.load(path)
        self.vectorizer = bundle["vectorizer"]
        self.scaler = bundle["scaler"]
        self.clf = bundle["clf"]
        self.meta: dict = bundle.get("meta", {})

    def _matrix(self, urls: list[str]):
        from scipy.sparse import csr_matrix, hstack

        texts = [F.canonical_for_model(u) for u in urls]
        x_text = self.vectorizer.transform(texts)
        x_lex = np.array([F.extract_features(u).as_vector() for u in urls], dtype=float)
        x_lex = self.scaler.transform(x_lex)
        return hstack([x_text, csr_matrix(x_lex)]).tocsr()

    def predict(self, urls: list[str]) -> list[float]:
        if not urls:
            return []
        proba = self.clf.predict_proba(self._matrix(urls))[:, 1]
        return [float(round(p, 4)) for p in proba]


class HeuristicUrlModel:
    """Fallback ohne trainiertes Modell: Score aus den Erklär-Regeln.

    Wird nur benutzt, wenn keine Modelldatei vorhanden ist (z. B. in CI).
    """

    meta = {"kind": "heuristic"}

    def predict(self, urls: list[str]) -> list[float]:
        out = []
        for u in urls:
            f = F.extract_features(u)
            s = (
                0.45 * f.has_ip_host
                + 0.45 * f.brand_lookalike
                + 0.25 * f.brand_in_subdomain_or_path
                + 0.30 * f.has_at
                + 0.20 * f.has_punycode
                + 0.20 * f.suspicious_tld
                + 0.10 * f.is_shortener
                + 0.10 * min(f.keyword_hits, 3)
                + 0.05 * (f.num_subdomains >= 3)
                + 0.05 * (f.url_length > 100)
            )
            out.append(round(min(1.0, s), 4))
        return out


class TextModel:
    """Platzhalter-Textmodell → delegiert an die Heuristiken.

    Eigenes Modell einbauen: diese Klasse so umschreiben, dass ``predict``
    ``TextVerdict(score=..., reasons=[...])`` aus deinem Klassifikator baut.
    """

    meta = {"kind": "heuristic"}

    def predict(self, text: str) -> TextVerdict:
        return score_text(text)


def load_url_model() -> SupportsUrlPredict:
    try:
        return UrlModel()
    except FileNotFoundError:
        return HeuristicUrlModel()
