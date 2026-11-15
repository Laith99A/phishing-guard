#!/usr/bin/env bash
# Phishing Guard – Backend starten (macOS / Linux)
set -e
cd "$(dirname "$0")/backend"

if [ ! -x ".venv/bin/python" ]; then
    echo "Erstelle virtuelle Umgebung ..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

echo
echo "Phishing Guard Backend läuft auf http://127.0.0.1:8000"
echo "Dieses Fenster offen lassen. Schließen = Backend aus."
echo
exec uvicorn app.main:app --port 8000
