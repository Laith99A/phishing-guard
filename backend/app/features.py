"""Lexikalische URL-Merkmale.

Alles hier arbeitet rein auf dem URL-String – es wird nichts im Netz
nachgeschlagen. Dadurch ist die Analyse schnell und datenschutzfreundlich:
Die URL verlässt den Rechner nicht (sofern das Backend lokal läuft).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

# Marken, die besonders häufig nachgeahmt werden (DE/International).
# Wird für Lookalike-Erkennung genutzt: "paypa1-login.net" → ähnelt "paypal".
BRANDS: tuple[str, ...] = (
    "paypal", "amazon", "sparkasse", "volksbank", "postbank", "commerzbank",
    "deutschebank", "ing", "dkb", "n26", "dhl", "hermes", "dpd", "ups",
    "microsoft", "office365", "outlook", "google", "apple", "icloud",
    "netflix", "spotify", "ebay", "kleinanzeigen", "telekom", "vodafone",
    "o2", "whatsapp", "instagram", "facebook", "linkedin", "github",
    "steam", "coinbase", "binance", "bitpanda", "elster", "bundesbank",
)

# TLDs, die in Phishing-Kampagnen überproportional vorkommen.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "zip", "mov", "top", "xyz", "club", "work", "click", "link", "gq",
    "tk", "ml", "cf", "ga", "buzz", "icu", "cam", "rest", "monster",
    "quest", "sbs", "cfd", "bond", "cyou", "lol", "su", "pw",
})

# Schlüsselwörter, die in Phishing-URLs typisch sind (DE/EN).
URL_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "sign-in", "anmelden", "verify", "verifizieren",
    "secure", "sicher", "account", "konto", "update", "aktualisieren",
    "confirm", "bestaetigen", "bestätigen", "password", "passwort",
    "bank", "wallet", "invoice", "rechnung", "zahlung", "payment",
    "paket", "sendung", "tracking", "unlock", "entsperren", "support",
)

# URL-Shortener: Ziel ist unbekannt → leicht erhöhter Verdacht.
SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "t.ly", "shorturl.at", "tiny.cc", "lnkd.in",
})

# Homoglyphen → ASCII-Normalisierung für den Lookalike-Vergleich.
_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "|": "l", "!": "i",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",  # kyrillisch
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
})

_URL_RE = re.compile(
    r"""(?xi)
    \b(?:https?://|www\.)            # Schema oder www.
    [^\s<>"'()\[\]{}]+               # bis zum nächsten Trenner
    """
)


@dataclass(frozen=True)
class UrlFeatures:
    """Numerische Merkmale einer URL (Eingabe für das ML-Modell)."""

    url_length: int
    host_length: int
    path_length: int
    num_dots: int
    num_hyphens: int
    num_digits: int
    num_subdomains: int
    num_query_params: int
    num_special: int
    has_ip_host: int
    has_at: int
    has_port: int
    has_https: int
    has_punycode: int
    suspicious_tld: int
    is_shortener: int
    keyword_hits: int
    brand_in_subdomain_or_path: int
    brand_lookalike: int
    digit_ratio: float

    def as_dict(self) -> dict[str, float]:
        return asdict(self)

    def as_vector(self) -> list[float]:
        """Merkmalsvektor für das ML-Modell.

        ``has_https`` wird bewusst ausgelassen: Der Trainingsdatensatz enthält
        fast keine Schemata, das Modell würde daraus nur Rauschen lernen. Für
        die Erklärung (``explain_url``) wird es trotzdem genutzt.
        """
        d = asdict(self)
        return [v for k, v in d.items() if k not in EXCLUDED_FROM_MODEL]


EXCLUDED_FROM_MODEL: frozenset[str] = frozenset({"has_https"})


def feature_names() -> list[str]:
    return [k for k in UrlFeatures.__dataclass_fields__ if k not in EXCLUDED_FROM_MODEL]


def canonical_for_model(raw: str) -> str:
    """Kanonische Form für die TF-IDF-Vektorisierung: ohne Schema, ohne
    führendes ``www.``, kleingeschrieben.

    Der Trainingsdatensatz liegt genau in dieser Form vor – so sehen Modell
    und Live-Eingabe dieselbe Verteilung.
    """
    url = normalize_url(raw)
    p = safe_split(url)
    host = p.hostname
    if host.startswith("www."):
        host = host[4:]
    rest = p.path
    if p.query:
        rest += "?" + p.query
    return (host + rest).lower().rstrip("/") or host


def normalize_url(raw: str) -> str:
    """Schema ergänzen, Whitespace entfernen – damit urlsplit sauber arbeitet."""
    url = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_urls(text: str) -> list[str]:
    """Alle URLs aus einem Freitext (z. B. Mail-Body) ziehen, Duplikate entfernen."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?")
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


# Bekannte Weiterleitungs-Wrapper: Gmail und Outlook packen externe Links in
# eigene Redirect-URLs. Ohne Auspacken sähe das Modell nur "google.com".
_REDIRECTORS: dict[str, tuple[str, ...]] = {
    "google.com": ("q", "url"),  # www.google.com/url?q=…
    "safelinks.protection.outlook.com": ("url",),
    "facebook.com": ("u",),  # l.facebook.com/l.php?u=…
    "linkedin.com": ("url",),  # linkedin.com/redir/redirect?url=…
    "youtube.com": ("q",),  # youtube.com/redirect?q=…
}


def unwrap_redirect(raw_url: str, max_depth: int = 3) -> str:
    """Löst bekannte Redirect-Wrapper auf und gibt die eigentliche Ziel-URL zurück.

    Kein Netzwerkzugriff – nur Parsen des Query-Strings. Unbekannte
    Weiterleitungen bleiben unverändert.
    """
    from urllib.parse import parse_qs, unquote

    url = raw_url
    for _ in range(max_depth):
        p = safe_split(normalize_url(url))
        host = p.hostname
        keys = next(
            (v for k, v in _REDIRECTORS.items() if host == k or host.endswith("." + k)),
            None,
        )
        if not keys or not p.query:
            return url
        qs = parse_qs(p.query, keep_blank_values=False)
        target = next((qs[k][0] for k in keys if k in qs and qs[k]), None)
        if not target:
            return url
        target = unquote(target)
        if not re.match(r"^https?://", target, re.I):
            return url
        url = target
    return url


def registrable_domain(host: str) -> str:
    """Grobe eTLD+1-Näherung ohne Public-Suffix-Liste.

    Behandelt gängige zweistufige Endungen wie co.uk / com.au korrekt.
    """
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    second_level = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if parts[-2] in second_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_lookalike(host: str) -> str | None:
    """Gibt die nachgeahmte Marke zurück, wenn der Domain-Name einer Marke
    ähnelt, aber nicht die echte Domain ist (z. B. ``paypa1.com``, ``sparkasse-login.de``).
    """
    dom = registrable_domain(host)
    label = dom.split(".")[0]
    label_norm = label.translate(_HOMOGLYPHS)

    for brand in BRANDS:
        if label == brand:
            return None  # echte Marken-Domain (paypal.com) – kein Lookalike
        if label_norm == brand and label != brand:
            return brand  # nur durch Homoglyphen "gleich" → Lookalike
        # Marke als Teil des Labels mit Zusatz: "sparkasse-login", "amazon-de"
        if brand in label_norm and label_norm != brand and len(brand) >= 4:
            return brand
        # Tippfehler-Distanz 1 bei längeren Marken: "amazom", "paypall"
        if len(brand) >= 5 and _levenshtein(label_norm, brand) == 1:
            return brand
    return None


@dataclass(frozen=True)
class _Parts:
    scheme: str
    netloc: str
    hostname: str
    port: int | None
    path: str
    query: str


def safe_split(url: str) -> _Parts:
    """urlsplit, das bei kaputten Eingaben (ungültiges IPv6, Port) nicht wirft.

    Phishing-URLs sind oft absichtlich missgebildet – die Analyse darf daran
    nicht scheitern.
    """
    try:
        p = urlsplit(url)
        hostname = (p.hostname or "").lower()
        try:
            port = p.port
        except ValueError:
            port = -1  # ungültiger Port → als "ungewöhnlich" werten
        return _Parts(p.scheme, p.netloc, hostname, port, p.path or "", p.query or "")
    except ValueError:
        # Manuelles Zerlegen: schema://netloc/path?query
        scheme, _, rest = url.partition("://")
        netloc, _, tail = rest.partition("/")
        path, _, query = ("/" + tail).partition("?")
        host = netloc.rsplit("@", 1)[-1].split(":")[0].strip("[]").lower()
        return _Parts(scheme.lower(), netloc, host, -1, path, query)


def extract_features(raw_url: str) -> UrlFeatures:
    url = normalize_url(raw_url)
    parts = safe_split(url)
    host = parts.hostname
    path = parts.path
    query = parts.query
    lower = url.lower()

    host_wo_port = host
    tld = host_wo_port.rsplit(".", 1)[-1] if "." in host_wo_port else ""
    is_ip = _is_ip(host_wo_port)
    subdomains = 0 if is_ip else max(0, host_wo_port.count(".") - 1)

    dom = registrable_domain(host_wo_port)
    sub_and_path = (host_wo_port.replace(dom, "", 1) + path).lower()
    brand_elsewhere = int(any(b in sub_and_path for b in BRANDS if len(b) >= 4))

    digits = sum(c.isdigit() for c in url)
    specials = sum(c in "-_~%&=?#" for c in url)

    return UrlFeatures(
        url_length=len(url),
        host_length=len(host_wo_port),
        path_length=len(path),
        num_dots=host_wo_port.count("."),
        num_hyphens=host_wo_port.count("-"),
        num_digits=digits,
        num_subdomains=subdomains,
        num_query_params=query.count("&") + (1 if query else 0),
        num_special=specials,
        has_ip_host=int(is_ip),
        has_at=int("@" in parts.netloc),
        has_port=int(parts.port is not None and parts.port not in (80, 443)),
        has_https=int(parts.scheme == "https"),
        has_punycode=int("xn--" in host_wo_port),
        suspicious_tld=int(tld in SUSPICIOUS_TLDS),
        is_shortener=int(dom in SHORTENERS),
        keyword_hits=sum(1 for k in URL_KEYWORDS if k in lower),
        brand_in_subdomain_or_path=brand_elsewhere,
        brand_lookalike=int(brand_lookalike(host_wo_port) is not None),
        digit_ratio=round(digits / max(1, len(url)), 4),
    )


def explain_url(raw_url: str) -> list[str]:
    """Menschlich lesbare Gründe (DE) – werden in der Extension angezeigt."""
    f = extract_features(raw_url)
    url = normalize_url(raw_url)
    host = safe_split(url).hostname
    reasons: list[str] = []

    if f.has_ip_host:
        reasons.append("Host ist eine IP-Adresse statt eines Domainnamens")
    if (b := brand_lookalike(host)):
        reasons.append(f"Domain ähnelt der Marke „{b}“, ist aber nicht deren echte Domain")
    if f.brand_in_subdomain_or_path:
        reasons.append("Markenname steckt in Subdomain oder Pfad, nicht in der eigentlichen Domain")
    if f.has_at:
        reasons.append("„@“ in der Adresse – alles davor wird vom Browser ignoriert")
    if f.has_punycode:
        reasons.append("Punycode-Domain (xn--) – kann Umlaute oder fremde Schriftzeichen tarnen")
    if f.suspicious_tld:
        reasons.append("Top-Level-Domain wird häufig für Phishing missbraucht")
    if f.is_shortener:
        reasons.append("URL-Shortener – das eigentliche Ziel ist nicht sichtbar")
    if f.num_subdomains >= 3:
        reasons.append(f"Ungewöhnlich viele Subdomains ({f.num_subdomains})")
    if f.num_hyphens >= 3:
        reasons.append("Viele Bindestriche im Hostnamen")
    if f.keyword_hits >= 2:
        reasons.append("Mehrere typische Phishing-Begriffe (Login, verifizieren, Konto …)")
    if f.url_length > 100:
        reasons.append(f"Sehr lange URL ({f.url_length} Zeichen)")
    if f.has_port:
        reasons.append("Ungewöhnlicher Port in der Adresse")
    if not f.has_https:
        reasons.append("Keine HTTPS-Verschlüsselung")
    return reasons
