from app.heuristics import score_text

PHISHING_DE = """Sehr geehrter Kunde,

Ihr Konto wurde vorübergehend gesperrt. Bitte bestätigen Sie innerhalb von 24 Stunden
Ihre Zugangsdaten, andernfalls wird Ihr Konto gelöscht.
"""

PHISHING_EN = """Dear Customer,

Your account has been suspended. Please verify your password within 48 hours,
otherwise legal action will be taken. Click here to confirm.
"""

HARMLESS_DE = """Hi Laith,

anbei die Folien von heute. Die Übung besprechen wir dann am Montag.

Viele Grüße
Anna
"""


def test_empty_text_scores_zero():
    assert score_text("").score == 0.0
    assert score_text("   \n ").score == 0.0


def test_german_phishing_scores_high():
    v = score_text(PHISHING_DE)
    assert v.score >= 0.6
    assert "urgency" in v.matched_rules
    assert "credentials" in v.matched_rules
    assert "generic_greeting" in v.matched_rules


def test_english_phishing_scores_high():
    v = score_text(PHISHING_EN)
    assert v.score >= 0.6
    assert {"urgency", "credentials", "threat"} <= set(v.matched_rules)


def test_harmless_mail_scores_low():
    v = score_text(HARMLESS_DE)
    assert v.score < 0.3
    assert v.reasons == []


def test_single_signal_stays_moderate():
    v = score_text("Bitte bestätigen Sie den Termin.")
    assert 0.0 < v.score < 0.5


def test_score_is_bounded():
    v = score_text(PHISHING_DE * 20 + PHISHING_EN * 20 + "!!!")
    assert 0.0 <= v.score <= 1.0
