"""Phishing Guard API.

Start lokal:  uvicorn app.main:app --reload --port 8000
Docs:         http://127.0.0.1:8000/docs
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from . import __version__
from . import features as F
from .allowlist import is_known_good
from .model import TextModel, load_url_model
from .schemas import (
    HealthResponse,
    TextRequest,
    TextResponse,
    UrlRequest,
    UrlResult,
    UrlsRequest,
    UrlsResponse,
    Verdict,
)

# Schwellen für die Einstufung. Bewusst konservativ, damit die Extension
# nicht jede zweite Seite rot markiert.
SUSPICIOUS_AT = 0.6
DANGEROUS_AT = 0.85


def to_verdict(score: float) -> Verdict:
    if score >= DANGEROUS_AT:
        return "dangerous"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "safe"


models: dict = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    models["url"] = load_url_model()
    models["text"] = TextModel()
    yield
    models.clear()


app = FastAPI(
    title="Phishing Guard API",
    version=__version__,
    description="Bewertet URLs und Mail-Texte auf Phishing-Merkmale. Läuft lokal, sendet nichts ins Netz.",
    lifespan=lifespan,
)

# Die Extension spricht aus einem chrome-extension://-Origin mit uns.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _score_urls(urls: list[str]) -> list[UrlResult]:
    """Pipeline pro URL: Allowlist → Modell → Einstufung + Begründung."""
    results: list[UrlResult | None] = [None] * len(urls)
    to_model: list[tuple[int, str]] = []

    # Redirect-Wrapper (Gmail, Outlook Safelinks …) auspacken: bewertet wird
    # das Ziel, zurückgegeben wird die Original-URL (damit die Extension
    # ihre Links wiederfindet).
    targets = [F.unwrap_redirect(u) for u in urls]

    for i, (u, t) in enumerate(zip(urls, targets, strict=True)):
        if is_known_good(t):
            results[i] = UrlResult(
                url=u, score=0.01, verdict="safe", reasons=["Bekannte, vertrauenswürdige Domain"]
            )
        else:
            to_model.append((i, u))

    if to_model:
        scores = models["url"].predict([targets[i] for i, _ in to_model])
        for (i, u), s in zip(to_model, scores, strict=True):
            t = targets[i]
            reasons = F.explain_url(t)
            if t != u:
                reasons.insert(0, f"Weiterleitung – eigentliches Ziel: {t[:120]}")
            results[i] = UrlResult(url=u, score=s, verdict=to_verdict(s), reasons=reasons)

    return [r for r in results if r is not None]


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> str:
    return """<!doctype html><html lang="de"><meta charset="utf-8">
<title>Phishing Guard</title>
<body style="font:16px/1.6 system-ui;max-width:560px;margin:60px auto;padding:0 16px">
<h1 style="font-size:22px">✅ Phishing Guard Backend läuft</h1>
<p>Dieses Fenster brauchst du nicht – die Browser-Extension spricht im Hintergrund mit dieser API.</p>
<ul>
<li><a href="/health">/health</a> – Status und Modell-Metriken</li>
<li><a href="/docs">/docs</a> – API direkt ausprobieren</li>
</ul>
<p>Nächster Schritt: Extension in Chrome laden (<code>chrome://extensions</code> → Entwicklermodus →
„Entpackte Erweiterung laden“ → Ordner <code>extension/</code>).</p>
</body></html>"""


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        url_model=getattr(models["url"], "meta", {}),
        text_model=getattr(models["text"], "meta", {}),
    )


@app.post("/analyze/url", response_model=UrlResult)
def analyze_url(req: UrlRequest) -> UrlResult:
    return _score_urls([req.url])[0]


@app.post("/analyze/urls", response_model=UrlsResponse)
def analyze_urls(req: UrlsRequest) -> UrlsResponse:
    # Duplikate nur einmal bewerten, Reihenfolge erhalten.
    unique = list(dict.fromkeys(req.urls))
    return UrlsResponse(results=_score_urls(unique))


@app.post("/analyze/text", response_model=TextResponse)
def analyze_text(req: TextRequest) -> TextResponse:
    tv = models["text"].predict(req.text)
    links = _score_urls(F.extract_urls(req.text))
    worst_link = max((link.score for link in links), default=0.0)

    # Gesamturteil: Text-Signale und gefährlichster Link kombiniert.
    # Ein gefährlicher Link allein reicht; Text allein braucht mehrere Signale.
    combined = max(worst_link, tv.score, 1 - (1 - tv.score) * (1 - 0.7 * worst_link))
    combined = round(min(1.0, combined), 3)

    return TextResponse(
        score=combined,
        verdict=to_verdict(combined),
        text_score=tv.score,
        text_reasons=tv.reasons,
        links=links,
    )
