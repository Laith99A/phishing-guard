import pytest

from app import features as F


def test_normalize_adds_scheme():
    assert F.normalize_url("example.com/x") == "http://example.com/x"
    assert F.normalize_url("https://example.com") == "https://example.com"


def test_extract_urls_dedupes_and_strips_punctuation():
    text = "Klick hier: https://evil.xyz/login. Oder www.evil.xyz/login, nochmal https://EVIL.xyz/login!"
    urls = F.extract_urls(text)
    assert urls == ["https://evil.xyz/login", "www.evil.xyz/login"]


@pytest.mark.parametrize(
    "host,expected",
    [
        ("www.google.com", "google.com"),
        ("mail.google.com", "google.com"),
        ("bbc.co.uk", "bbc.co.uk"),
        ("news.bbc.co.uk", "bbc.co.uk"),
        ("localhost", "localhost"),
        ("amazon.de.evil.xyz", "evil.xyz"),
    ],
)
def test_registrable_domain(host, expected):
    assert F.registrable_domain(host) == expected


@pytest.mark.parametrize(
    "host,brand",
    [
        ("paypa1.com", "paypal"),
        ("paypall.com", "paypal"),
        ("sparkasse-login.de", "sparkasse"),
        ("amazom.de", "amazon"),
        ("xn--pypal-4ve.com", None),  # Punycode wird separat erkannt
    ],
)
def test_brand_lookalike_detected(host, brand):
    assert F.brand_lookalike(host) == brand


@pytest.mark.parametrize("host", ["paypal.com", "amazon.de", "google.com", "h-da.de", "ing.de"])
def test_real_brand_domain_is_not_lookalike(host):
    assert F.brand_lookalike(host) is None


def test_features_ip_host():
    f = F.extract_features("http://192.168.4.3/sparkasse/login.php")
    assert f.has_ip_host == 1
    assert f.brand_in_subdomain_or_path == 1
    assert f.has_https == 0


def test_features_at_and_port():
    f = F.extract_features("http://paypal.com@evil.xyz:8081/x")
    assert f.has_at == 1
    assert f.has_port == 1
    assert f.suspicious_tld == 1


def test_features_do_not_crash_on_malformed():
    for u in ["http://[::1/bad", "http://host:notaport/x", "", "   ", "http://", "::::"]:
        F.extract_features(u)
        F.explain_url(u)


def test_vector_excludes_https_and_matches_names():
    f = F.extract_features("https://example.com")
    assert len(f.as_vector()) == len(F.feature_names())
    assert "has_https" not in F.feature_names()


def test_canonical_for_model():
    assert F.canonical_for_model("https://www.Google.com/") == "google.com"
    assert F.canonical_for_model("google.com") == "google.com"
    assert F.canonical_for_model("http://x.de/a?b=1") == "x.de/a?b=1"


@pytest.mark.parametrize(
    "wrapped,target",
    [
        ("https://www.google.com/url?q=http://evil.xyz/login&sa=D", "http://evil.xyz/login"),
        ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.xyz%2Fx&data=1", "https://evil.xyz/x"),
        ("https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.xyz", "https://evil.xyz"),
        ("https://github.com/Laith99A", "https://github.com/Laith99A"),  # kein Wrapper
        ("https://www.google.com/url?q=javascript:alert(1)", "https://www.google.com/url?q=javascript:alert(1)"),
    ],
)
def test_unwrap_redirect(wrapped, target):
    assert F.unwrap_redirect(wrapped) == target


def test_explain_mentions_lookalike():
    reasons = F.explain_url("http://paypa1-login.com/verify")
    assert any("paypal" in r for r in reasons)
    assert any("HTTPS" in r for r in reasons)
