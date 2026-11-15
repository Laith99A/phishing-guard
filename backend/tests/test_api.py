import pytest
from fastapi.testclient import TestClient

from app.main import app, to_verdict


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "kind" in body["url_model"]


def test_to_verdict_thresholds():
    assert to_verdict(0.0) == "safe"
    assert to_verdict(0.59) == "safe"
    assert to_verdict(0.6) == "suspicious"
    assert to_verdict(0.85) == "dangerous"


def test_known_good_domain_is_safe(client):
    r = client.post("/analyze/url", json={"url": "https://paypal.com/signin"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "safe"


def test_lookalike_is_flagged(client):
    r = client.post("/analyze/url", json={"url": "http://paypa1-login.com/verify"})
    body = r.json()
    assert body["verdict"] in ("suspicious", "dangerous")
    assert any("paypal" in x for x in body["reasons"])


def test_ip_host_is_flagged(client):
    r = client.post("/analyze/url", json={"url": "http://192.168.4.3/sparkasse/login.php"})
    assert r.json()["verdict"] in ("suspicious", "dangerous")


def test_batch_dedupes_and_keeps_order(client):
    urls = ["https://github.com/a", "http://paypa1-login.com/verify", "https://github.com/a"]
    r = client.post("/analyze/urls", json={"urls": urls})
    results = r.json()["results"]
    assert [x["url"] for x in results] == ["https://github.com/a", "http://paypa1-login.com/verify"]


def test_batch_rejects_empty_and_too_many(client):
    assert client.post("/analyze/urls", json={"urls": []}).status_code == 422
    assert client.post("/analyze/urls", json={"urls": ["x"] * 301}).status_code == 422


def test_redirect_wrapper_is_unwrapped(client):
    wrapped = "https://www.google.com/url?q=http://paypa1-login.com/verify&sa=D"
    body = client.post("/analyze/url", json={"url": wrapped}).json()
    assert body["url"] == wrapped  # Original-URL kommt zurück
    assert body["verdict"] in ("suspicious", "dangerous")
    assert body["reasons"][0].startswith("Weiterleitung")


def test_text_phishing(client):
    text = (
        "Sehr geehrter Kunde, Ihr Konto wurde gesperrt. Bitte bestätigen Sie innerhalb von 24 Stunden "
        "Ihre Zugangsdaten unter http://sparkasse-sicherheit.top/konto/verifizieren, "
        "andernfalls wird es gelöscht."
    )
    body = client.post("/analyze/text", json={"text": text}).json()
    assert body["verdict"] == "dangerous"
    assert body["text_score"] > 0.5
    assert len(body["links"]) == 1
    assert body["links"][0]["verdict"] == "dangerous"


def test_text_harmless(client):
    text = "Hi Laith, anbei die Folien: https://github.com/Laith99A/file-integrity-monitor – bis Montag!"
    body = client.post("/analyze/text", json={"text": text}).json()
    assert body["verdict"] == "safe"
    assert body["links"][0]["verdict"] == "safe"


def test_text_requires_content(client):
    assert client.post("/analyze/text", json={"text": ""}).status_code == 422
