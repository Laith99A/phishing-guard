"""Regelbasierte Text-Analyse für Mail-Inhalte (Deutsch & Englisch).

Dies ist bewusst ein einfacher, erklärbarer Ansatz. Die Schnittstelle
``score_text(text) -> TextVerdict`` ist so gebaut, dass sie 1:1 durch ein
trainiertes Textmodell (TF-IDF + Klassifikator) ersetzt werden kann –
siehe ``model.py`` → ``TextModel``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Jede Regel: (Name, kompiliertes Muster, Gewicht, Begründung)
_RULES: list[tuple[str, re.Pattern[str], float, str]] = [
    (
        "urgency",
        re.compile(
            r"\b(sofort|umgehend|dringend|innerhalb von \d+ ?(stunden|tagen)|"
            r"letzte (warnung|mahnung)|frist|gesperrt|sperrung|deaktiviert|"
            r"immediately|urgent|within \d+ ?(hours|days)|final (notice|warning)|"
            r"suspended|will be (locked|closed|terminated))\b",
            re.I,
        ),
        0.25,
        "Erzeugt Zeitdruck (sofort, Frist, Sperrung …)",
    ),
    (
        "credentials",
        re.compile(
            r"\b(passwort|kennwort|pin|tan|zugangsdaten|anmeldedaten|"
            r"kreditkarte|iban|kontonummer|"
            r"password|credentials|credit card|card number|ssn|social security)\b",
            re.I,
        ),
        0.30,
        "Fragt nach Zugangs- oder Zahlungsdaten",
    ),
    (
        "verify_action",
        re.compile(
            r"\b(verifizier\w*|bestätig\w*|aktualisier\w*|best[aä]tigen sie|"
            r"klicken sie (hier|auf)|hier klicken|"
            r"verify|confirm|validate|update your|click (here|the link|below))\b",
            re.I,
        ),
        0.20,
        "Fordert zur Bestätigung/Verifizierung über einen Link auf",
    ),
    (
        "threat",
        re.compile(
            r"\b(andernfalls|ansonsten|sonst wird|wird (gesperrt|gelöscht|geschlossen)|"
            r"rechtliche schritte|inkasso|mahngebühr|"
            r"otherwise|or your account|legal action|penalt(y|ies)|debt collection)\b",
            re.I,
        ),
        0.20,
        "Droht mit Konsequenzen",
    ),
    (
        "reward",
        re.compile(
            r"\b(gewonnen|gewinn|gutschein|prämie|erstattung|rückerstattung|"
            r"you (have )?won|prize|gift ?card|refund|reward|lottery|claim your)\b",
            re.I,
        ),
        0.15,
        "Verspricht Gewinn, Gutschein oder Erstattung",
    ),
    (
        "generic_greeting",
        re.compile(
            r"^(\s*)(sehr geehrte[r]? (kunde|kundin|nutzer|damen und herren)|"
            r"lieber kunde|liebe kundin|hallo kunde|"
            r"dear (customer|user|member|valued|sir|madam|client))",
            re.I | re.M,
        ),
        0.15,
        "Unpersönliche Anrede („Sehr geehrter Kunde“)",
    ),
    (
        "parcel",
        re.compile(
            r"\b(paket|sendung|zustellung|zollgebühr|lieferung konnte nicht|"
            r"package|parcel|delivery (failed|attempt)|customs fee|shipment)\b",
            re.I,
        ),
        0.10,
        "Paket-/Zustell-Masche",
    ),
]

_EXCESS_PUNCT = re.compile(r"[!]{2,}|[?]{2,}")


@dataclass
class TextVerdict:
    score: float  # 0.0 (harmlos) … 1.0 (sehr verdächtig)
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)


def score_text(text: str) -> TextVerdict:
    """Bewertet einen Mail-Text anhand gewichteter Regeln.

    Der Score ist eine gesättigte Summe: viele schwache Signale zusammen
    ergeben einen hohen Score, ein einzelnes Signal bleibt moderat.
    """
    if not text or not text.strip():
        return TextVerdict(score=0.0)

    total = 0.0
    reasons: list[str] = []
    matched: list[str] = []

    for name, pattern, weight, reason in _RULES:
        hits = len(pattern.findall(text))
        if hits:
            # Mehrfachtreffer zählen leicht mehr, aber nicht linear.
            total += weight * min(1.0 + 0.25 * (hits - 1), 1.75)
            reasons.append(reason)
            matched.append(name)

    if _EXCESS_PUNCT.search(text):
        total += 0.05
        reasons.append("Auffällige Zeichensetzung (!!!, ???)")
        matched.append("punctuation")

    # Sättigung auf [0, 1]
    score = 1.0 - (1.0 / (1.0 + total * 2.2)) if total > 0 else 0.0
    return TextVerdict(score=round(min(score, 1.0), 3), reasons=reasons, matched_rules=matched)
