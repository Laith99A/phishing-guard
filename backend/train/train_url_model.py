"""Trainiert das URL-Basis-Modell.

Datensatz: ``data/urls.csv`` mit Spalten ``url,label`` (label: good/bad).
Quelle (öffentlich): github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs

Aufruf aus dem backend/-Ordner:
    python -m train.train_url_model --data data/urls.csv --sample 120000

Modell: Char-N-Gramm-TF-IDF (3–5) auf dem URL-String + 20 lexikalische
Merkmale (features.py) → Logistische Regression. Bewusst klein gehalten,
damit die Modelldatei ins Repo passt und die Inferenz in Millisekunden läuft.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import features as F  # noqa: E402

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"


def load_data(path: Path, sample: int | None, seed: int) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    df["y"] = (df["label"].str.lower() == "bad").astype(int)
    if sample and sample < len(df):
        # Stratifiziert ziehen, damit das Klassenverhältnis erhalten bleibt.
        df = df.groupby("y").sample(frac=sample / len(df), random_state=seed).reset_index(drop=True)
    return df


def lexical_matrix(urls: pd.Series) -> np.ndarray:
    return np.array([F.extract_features(u).as_vector() for u in urls], dtype=float)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("data/urls.csv"))
    ap.add_argument("--sample", type=int, default=120_000, help="0 = alle Zeilen")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=MODEL_DIR / "url_model.joblib")
    args = ap.parse_args()

    t0 = time.time()
    df = load_data(args.data, args.sample or None, args.seed)
    print(f"Daten: {len(df):,} URLs, davon {df.y.mean():.1%} bösartig")

    x_train, x_test, y_train, y_test = train_test_split(
        df["url"], df["y"], test_size=0.2, random_state=args.seed, stratify=df["y"]
    )

    print("Lexikalische Merkmale …")
    lex_train = lexical_matrix(x_train)
    lex_test = lexical_matrix(x_test)
    scaler = StandardScaler().fit(lex_train)

    print("TF-IDF (Char-N-Gramme 3–5) …")
    vec = TfidfVectorizer(
        analyzer="char", ngram_range=(3, 5), min_df=5, max_features=60_000,
        sublinear_tf=True, lowercase=False, preprocessor=F.canonical_for_model,
    )
    xt_train = vec.fit_transform(x_train)
    xt_test = vec.transform(x_test)

    X_train = hstack([xt_train, csr_matrix(scaler.transform(lex_train))]).tocsr()
    X_test = hstack([xt_test, csr_matrix(scaler.transform(lex_test))]).tocsr()

    print("Training …")
    clf = LogisticRegression(
        C=2.0, max_iter=2000, solver="liblinear", random_state=args.seed
    )
    clf.fit(X_train, y_train)

    proba = clf.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_test, pred, average="binary")
    auc = roc_auc_score(y_test, proba)
    cm = confusion_matrix(y_test, pred).tolist()

    print("\n" + classification_report(y_test, pred, target_names=["good", "bad"], digits=3))
    print(f"ROC-AUC: {auc:.4f}   Konfusionsmatrix [[TN, FP], [FN, TP]]: {cm}")

    meta = {
        "kind": "tfidf_char(3,5)+lexical -> logreg",
        "trained_at": time.strftime("%Y-%m-%d"),
        "n_train": int(len(x_train)),
        "n_test": int(len(x_test)),
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(auc), 4),
        "confusion_matrix": cm,
        "features": F.feature_names(),
        "dataset": "faizann24/Using-machine-learning-to-detect-malicious-URLs (data.csv)",
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vec, "scaler": scaler, "clf": clf, "meta": meta}, args.out, compress=3)
    (args.out.with_suffix(".json")).write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    print(f"\nGespeichert: {args.out} ({args.out.stat().st_size / 1e6:.1f} MB) in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
