"""Allowlist bekannter, vertrauenswürdiger Domains.

Ein ML-Modell kann nicht wissen, dass ``paypal.com`` die echte PayPal-Domain
ist – es sieht nur „Marke + login“ und schlägt an. Deshalb werden bekannte
Domains vor dem Modell abgefangen. So machen es auch kommerzielle Produkte
(zusätzlich zu Reputations-Feeds).

Eigene Einträge: Datei ``models/allowlist.txt`` (eine Domain pro Zeile) oder
Umgebungsvariable ``PG_ALLOWLIST_FILE``.

Wichtig: Es wird die *registrierbare Domain* verglichen (eTLD+1). Eine
Subdomain wie ``mail.google.com`` zählt also als ``google.com``. Ein Lookalike
wie ``google.com.evil.xyz`` zählt als ``evil.xyz`` – und wird NICHT freigegeben.
"""

from __future__ import annotations

import os
from pathlib import Path

from .features import normalize_url, registrable_domain, safe_split

KNOWN_GOOD: frozenset[str] = frozenset({
    # Tech / Plattformen
    "google.com", "google.de", "youtube.com", "gmail.com", "googleapis.com",
    "microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com",
    "apple.com", "icloud.com", "amazon.com", "amazon.de", "aws.amazon.com",
    "github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com",
    "wikipedia.org", "wikimedia.org", "mozilla.org", "python.org", "npmjs.com",
    "pypi.org", "docker.com", "kaggle.com", "huggingface.co", "arxiv.org",
    "linkedin.com", "xing.com", "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "reddit.com", "discord.com", "telegram.org", "signal.org",
    "netflix.com", "spotify.com", "twitch.tv", "steampowered.com", "zoom.us",
    "dropbox.com", "notion.so", "slack.com", "atlassian.com", "trello.com",
    "cloudflare.com", "digitalocean.com", "hetzner.com", "ionos.de", "strato.de",
    "adobe.com", "canva.com", "figma.com", "openai.com", "anthropic.com",
    # Zahlung / Banken (DE)
    "paypal.com", "paypal.de", "klarna.com", "stripe.com",
    "sparkasse.de", "volksbank.de", "vr.de", "postbank.de", "commerzbank.de",
    "deutsche-bank.de", "ing.de", "dkb.de", "n26.com", "comdirect.de",
    "consorsbank.de", "targobank.de", "hypovereinsbank.de", "santander.de",
    "bundesbank.de", "scalable.capital", "traderepublic.com",
    # Logistik / Handel (DE)
    "dhl.de", "dhl.com", "deutschepost.de", "hermesworld.com", "myhermes.de",
    "dpd.com", "dpd.de", "ups.com", "fedex.com", "gls-group.eu",
    "ebay.de", "ebay.com", "kleinanzeigen.de", "otto.de", "zalando.de",
    "mediamarkt.de", "saturn.de", "lidl.de", "aldi.de", "rewe.de", "dm.de",
    "idealo.de", "check24.de", "bahn.de", "flixbus.de", "lufthansa.com",
    # Telekommunikation / Behörden / Bildung (DE)
    "telekom.de", "t-online.de", "vodafone.de", "o2online.de", "1und1.de",
    "web.de", "gmx.de", "gmx.net", "posteo.de", "mailbox.org",
    "bund.de", "bundesregierung.de", "bsi.bund.de", "elster.de", "arbeitsagentur.de",
    "deutsche-rentenversicherung.de", "bmbf.de", "bafoeg-digital.de",
    "h-da.de", "tu-darmstadt.de", "uni-frankfurt.de", "fraunhofer.de", "dfn.de",
    # Nachrichten
    "tagesschau.de", "zdf.de", "ard.de", "spiegel.de", "zeit.de", "faz.net",
    "sueddeutsche.de", "heise.de", "golem.de", "t3n.de", "bbc.co.uk",
    "nytimes.com", "theguardian.com", "reuters.com",
    # Sicherheit / Tools
    "virustotal.com", "haveibeenpwned.com", "owasp.org", "mitre.org",
    "nist.gov", "cisa.gov", "letsencrypt.org",
})

# Ganze Endungen, die nur mit Nachweis vergeben werden.
TRUSTED_SUFFIXES: tuple[str, ...] = (".gov", ".edu", ".mil", ".gov.uk", ".ac.uk", ".bund.de")

_extra: set[str] = set()


def _load_extra() -> None:
    default = Path(__file__).resolve().parent.parent / "models" / "allowlist.txt"
    path = Path(os.environ.get("PG_ALLOWLIST_FILE", default))
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                _extra.add(line)


_load_extra()


def is_known_good(url: str) -> bool:
    host = safe_split(normalize_url(url)).hostname
    if not host:
        return False
    dom = registrable_domain(host)
    if dom in KNOWN_GOOD or dom in _extra:
        return True
    return any(host.endswith(s) for s in TRUSTED_SUFFIXES)
