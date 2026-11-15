# Phishing Guard

Browser-Extension, die verdächtige Links auf jeder Webseite markiert und eingefügte Mail-Texte auf Phishing prüft. Die Analyse läuft lokal über eine FastAPI mit einem scikit-learn-Modell – es werden keine Daten an Dritte geschickt.

![CI](https://github.com/Laith99A/phishing-guard/actions/workflows/ci.yml/badge.svg)

<!-- Screenshots: docs/screenshot-popup.png, docs/screenshot-links.png -->

## Was es macht

- **Links markieren:** Auf jeder Seite werden externe Links bewertet. Verdächtige bekommen eine gelbe, gefährliche eine rote Wellenlinie plus Hinweis-Badge; der Tooltip nennt die Gründe.
- **Seiten-Warnung:** Sieht die aufgerufene Seite selbst nach Phishing aus, erscheint ein Banner („Gib hier keine Zugangsdaten ein“).
- **Mail-Check im Popup:** Mail-Text oder URL einfügen → Phishing-Wahrscheinlichkeit, Auffälligkeiten im Text (DE/EN) und Bewertung aller enthaltenen Links.
- **Redirect-Auflösung:** Gmail- und Outlook-Safelinks-Wrapper werden ausgepackt, bewertet wird das echte Ziel.
- **Badge:** Das Icon zeigt die Zahl markierter Links auf dem aktuellen Tab.

## Architektur

```
┌──────────────────────────── Browser ────────────────────────────┐
│  content.js            popup.js             options.js           │
│  (Links sammeln,       (Text prüfen,        (API-URL,            │
│   markieren, Banner)    Ergebnis anzeigen)   Markierung an/aus)  │
│        │                     │                                   │
│        └──────── chrome.runtime.sendMessage ────────┐            │
│                                                     ▼            │
│                              background.js (Service Worker)      │
│                              Cache (30 min) · Badge · fetch()    │
└─────────────────────────────────────┬────────────────────────────┘
                                      │ HTTP, JSON
                                      ▼
┌──────────────────────── FastAPI (127.0.0.1:8000) ────────────────┐
│  POST /analyze/urls  ──►  unwrap_redirect ──► Allowlist ──► Modell│
│  POST /analyze/text  ──►  Heuristiken (DE/EN) + Links wie oben    │
│                                                                   │
│  Modell: Char-N-Gramm-TF-IDF (3–5) + 19 lexikalische Merkmale     │
│          → Logistische Regression (scikit-learn, 1 MB)            │
└───────────────────────────────────────────────────────────────────┘
```

**Pipeline pro URL:** Redirect auspacken → bekannte Domain? (Allowlist, eTLD+1) → sonst ML-Score → Einstufung (`safe` < 0,6 ≤ `suspicious` < 0,85 ≤ `dangerous`) → erklärbare Gründe aus den lexikalischen Merkmalen (IP-Host, Marken-Lookalike, Punycode, verdächtige TLD, Shortener …).

## Modell

Basis-Modell, trainiert auf einem öffentlichen Datensatz mit ~420 000 URLs (gut/bösartig), 120 000 stratifiziert gezogen, 80/20-Split:

| Metrik (Klasse „bösartig“) | Wert |
|---|---|
| Precision | 0,979 |
| Recall | 0,847 |
| F1 | 0,908 |
| ROC-AUC | 0,991 |
| Accuracy gesamt | 97,2 % |
| Falsch-Positiv-Rate | 0,35 % (71 / 20 122) |

Die Schwellen sind bewusst auf **Precision** optimiert: Eine Extension, die jede zweite Seite rot markiert, wird nach einem Tag deinstalliert. Der Kompromiss ist ein niedrigerer Recall – darum zusätzlich die regelbasierten Merkmale, die typische Muster (Lookalike-Domains, IP-Hosts) auch dann treffen, wenn das Modell unsicher ist.

Details und Konfusionsmatrix: `backend/models/url_model.json`.

### Eigenes Modell einhängen

Die API kennt nur die Schnittstelle in `backend/app/model.py`:

```python
class UrlModel:
    def predict(self, urls: list[str]) -> list[float]: ...   # Wahrscheinlichkeit je URL

class TextModel:
    def predict(self, text: str) -> TextVerdict: ...          # score + reasons
```

- **URL-Modell** neu trainieren: `cd backend && python -m train.train_url_model --data data/urls.csv`
- **Text-Modell:** `TextModel.predict` aktuell regelbasiert (`heuristics.py`). Ein trainierter Klassifikator (z. B. TF-IDF + Logistische Regression auf einem Phishing-Mail-Datensatz) ersetzt die Klasse 1:1.

## Installation

### Backend

Am einfachsten: `start-backend.bat` (Windows) bzw. `./start-backend.sh` (macOS/Linux) doppelklicken – legt beim ersten Mal die virtuelle Umgebung an und startet die API. Fenster offen lassen.

Manuell:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

API-Doku: http://127.0.0.1:8000/docs

Oder mit Docker:

```bash
docker build -t phishing-guard ./backend
docker run -p 8000:8000 phishing-guard
```

### Extension (Chrome / Edge / Brave)

1. `chrome://extensions` öffnen, **Entwicklermodus** aktivieren
2. **Entpackte Erweiterung laden** → Ordner `extension/` wählen
3. Backend läuft? Der Punkt im Popup wird grün.

Zum Ausprobieren: `docs/demo.html` im Browser öffnen – die Seite enthält Testlinks, die markiert werden sollten. Beispiel-Mail zum Einfügen: `docs/beispiel-mail.txt`.

### Entwicklung

```bash
cd backend
pip install -r requirements-dev.txt
pytest -q          # 46 Tests
ruff check .
```

CI (GitHub Actions) führt Lint, Tests, einen Manifest-/Syntax-Check der Extension und einen Docker-Smoke-Test aus.

## Datenschutz

- Alle Bewertungen laufen gegen das lokale Backend. Nichts verlässt den Rechner.
- Die Extension liest nur `href`-Attribute und den im Popup eingefügten Text. Sie füllt keine Formulare aus und schickt nichts ab.
- Keine Telemetrie, kein Tracking, keine externen Reputationsdienste.

## Grenzen

- Das URL-Modell kennt nur lexikalische Merkmale – keine Domain-Alter, keine Zertifikate, keine Reputationslisten. Eine frische Phishing-Domain mit unauffälligem Namen kann durchrutschen.
- Der Trainingsdatensatz ist international und etwas älter; deutsche Phishing-Muster sind nur über die handgeschriebenen Merkmale (Marken, Schlüsselwörter) abgedeckt.
- Die Allowlist ist statisch. Eigene Domains: `backend/models/allowlist.txt` (eine pro Zeile).
- Firefox braucht ein leicht angepasstes Manifest (`background.scripts` statt `service_worker`).

## Roadmap

- [ ] Text-Modell auf echtem Phishing-Mail-Datensatz trainieren (ersetzt Heuristiken)
- [ ] Gmail / Outlook Web: Analyse direkt in der geöffneten Mail statt über das Popup
- [ ] Domain-Alter über RDAP als zusätzliches Merkmal (optional, da Netzwerkzugriff)
- [ ] Firefox-Manifest
- [ ] Feedback-Button („Fehlalarm melden“) zum Sammeln eigener Trainingsdaten

## Projektstruktur

```
backend/
  app/
    main.py         FastAPI-Endpoints, Pipeline, Schwellen
    features.py     URL-Merkmale, Lookalike-Erkennung, Redirect-Auflösung, Erklärungen
    heuristics.py   Regelbasierte Textanalyse (DE/EN)
    allowlist.py    Bekannte Domains
    model.py        Modell-Schnittstelle (hier eigenes Modell einhängen)
    schemas.py      Pydantic-Schemas
  train/
    train_url_model.py
  models/
    url_model.joblib   trainiertes Basis-Modell (1 MB)
    url_model.json     Metriken und Metadaten
  tests/
extension/
  manifest.json   Manifest V3
  background.js   Service Worker: API-Aufrufe, Cache, Badge
  content.js      Links sammeln und markieren, Seiten-Banner
  popup.*         Mail-Check
  options.*       Einstellungen
docs/
  demo.html, beispiel-mail.txt
```

## Lizenz

MIT
