@echo off
REM Phishing Guard – Backend per Doppelklick starten (Windows)
cd /d "%~dp0backend"

if not exist ".venv\Scripts\python.exe" (
    echo Erstelle virtuelle Umgebung ...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo.
echo Phishing Guard Backend laeuft auf http://127.0.0.1:8000
echo Dieses Fenster offen lassen. Schliessen = Backend aus.
echo.
uvicorn app.main:app --port 8000
pause
