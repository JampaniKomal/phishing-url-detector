"""Features computed from the URL string alone, with no network access.

v1_features() reproduces the 13 lexical and structural counts of the original
notebooks. FEATURES keeps v1's sound counts, replaces its two broken flags, and
adds host structure, randomness, sensitive words, free-hosting platforms and the
lookalike checks.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache
from urllib.parse import urlparse

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from . import lookalike
from .urlparts import parse

SHORTENERS = frozenset(
    "bit.ly goo.gl tinyurl.com ow.ly t.co is.gd buff.ly adf.ly bit.do cutt.ly rebrand.ly shorturl.at tiny.cc "
    "rb.gy t.ly s.id lnkd.in db.tt qr.ae v.gd x.co soo.gd shorte.st".split()
)
# Sites where anyone can publish under a shared domain; phishing pages are often
# hosted there, so the registered domain says little about who runs the page.
HOSTING = frozenset(
    "000webhostapp.com blogspot.com wordpress.com weebly.com wixsite.com appspot.com firebaseapp.com web.app "
    "github.io netlify.app vercel.app glitch.me herokuapp.com pages.dev workers.dev sharepoint.com "
    "googleusercontent.com sites.google.com codesandbox.io repl.co azurewebsites.net ngrok.io ngrok-free.app "
    "webflow.io godaddysites.com squarespace.com tumblr.com blogger.com mystrikingly.com yolasite.com "
    "square.site r2.dev onrender.com webadorsite.com".split()
)
SENSITIVE_WORDS = (
    "login", "signin", "logon", "verify", "verification", "account", "update", "secure", "security", "banking",
    "confirm", "password", "passwd", "webscr", "cmd", "wallet", "unlock", "suspend", "recover", "billing",
    "invoice", "payment", "authenticate", "auth", "validation", "support", "customer", "service", "free", "bonus",
)  # fmt: skip
COMMON_TLDS = frozenset("com org net edu gov in uk de fr it es nl ca au jp br ru ch se no fi dk pl be at io co".split())

V1_FEATURES = [
    "url_length", "hostname_length", "path_length", "count_hyphens", "count_dots", "count_at",
    "count_questionmark", "count_equals", "count_slashes", "count_digits", "has_ip", "has_https", "is_shortened",
]  # fmt: skip


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


_V1_IP = re.compile(
    r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\."
    r"([01]?\d\d?|2[0-4]\d|25[0-5])\/)|"
    r"((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2}))"
    r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:)"
)
_V1_SHORT = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|zpr\.io|tcrn\.ch|"
    r"filoops\.info|v\.gd|tr\.im|link\.zip\.net"
)


def v1_features(url: str) -> dict[str, float]:
    """The 13 features of v1's notebook 02, reproduced exactly, bugs included:
    its IPv4 pattern needs a "/" inside the host name, so it never matches (0 of
    the 97 IP-address URLs in the data), and its shortener pattern searches the
    whole URL, so its "t.co" matches microsoft.com and 1,401 URLs are "shortened".
    Kept for the baseline in the benchmark; v2 uses is_ip_host and is_shortener."""
    u = urlparse(url)
    return {
        "url_length": len(url),
        "hostname_length": len(u.netloc),
        "path_length": len(u.path),
        "count_hyphens": url.count("-"),
        "count_dots": url.count("."),
        "count_at": url.count("@"),
        "count_questionmark": url.count("?"),
        "count_equals": url.count("="),
        "count_slashes": url.count("/"),
        "count_digits": sum(c.isdigit() for c in url),
        "has_ip": float(bool(_V1_IP.search(u.netloc))),
        "has_https": float(u.scheme == "https"),
        "is_shortened": float(bool(_V1_SHORT.search(url))),
    }


def extract(url: str) -> dict[str, float]:
    p = parse(url)
    host = p.host
    path = p.path
    words = re.split(r"[^a-z0-9]+", url.lower())
    tokens_host = [t for t in re.split(r"[.-]", host) if t]
    tokens_path = [t for t in re.split(r"[/._=?&-]", path + "?" + p.query) if t]
    findings = lookalike.find(p)
    brand_sim = 0.0
    if p.domain and not p.is_ip:
        for brand in lookalike.BRANDS:
            if len(brand) >= 5:
                d = lookalike.edit_distance(p.domain, brand, limit=len(brand))
                brand_sim = max(brand_sim, 1 - d / len(brand))
    f = {k: v for k, v in v1_features(url).items() if k not in ("has_ip", "is_shortened")}
    f.update(
        {
            "is_shortener": int(p.registered in SHORTENERS),
            "query_length": len(p.query),
            "host_dots": host.count("."),
            "subdomain_levels": len(p.subdomain.split(".")) if p.subdomain else 0,
            "host_hyphens": host.count("-"),
            "host_digits": sum(c.isdigit() for c in host),
            "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
            "host_entropy": _entropy(host),
            "url_entropy": _entropy(url),
            "longest_host_token": max((len(t) for t in tokens_host), default=0),
            "longest_path_token": max((len(t) for t in tokens_path), default=0),
            "path_segments": len([s for s in path.split("/") if s]),
            "count_ampersand": url.count("&"),
            "count_percent": url.count("%"),
            "count_underscore": url.count("_"),
            "count_tilde": url.count("~"),
            "double_slash_in_path": int("//" in path),
            "has_port": int(p.port is not None),
            "is_ip_host": int(p.is_ip),
            "is_punycode": int("xn--" in host),
            "www_prefix": int(host.startswith("www.")),
            "tld_common": int(p.suffix.split(".")[-1] in COMMON_TLDS) if p.suffix else 0,
            "tld_length": len(p.suffix.split(".")[-1]) if p.suffix else 0,
            "free_hosting": int(p.registered in HOSTING or any(host.endswith("." + h) for h in HOSTING)),
            "sensitive_words": sum(w in words for w in SENSITIVE_WORDS),
            "php_or_html": int(bool(re.search(r"\.(php|html?|aspx?)$", path.lower()))),
            "email_in_url": int(bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", url[len(p.scheme) + 3 :]))),
            "brand_similarity": round(brand_sim, 4),
            "lookalike_severity": lookalike.strongest(findings),
            "official_brand_domain": int(p.registered in lookalike.OFFICIAL),
        }
    )
    return {k: float(v) for k, v in f.items()}


FEATURES = list(extract("http://example.com/").keys())


@lru_cache(maxsize=200_000)
def vector(url: str) -> tuple[float, ...]:
    """extract() as a tuple in FEATURES order, cached: cross-validation asks for
    the same URL's features once per fold."""
    f = extract(url)
    return tuple(f[k] for k in FEATURES)


class URLFeatures(BaseEstimator, TransformerMixin):
    """Turns raw URLs into a feature matrix, so a whole model is one pipeline
    from URL strings to a prediction."""

    def __init__(self, names: tuple[str, ...] | None = None):
        self.names = names

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        cols = [FEATURES.index(c) for c in self.names] if self.names else list(range(len(FEATURES)))
        return np.array([[v[i] for i in cols] for v in map(vector, X)], dtype=float)

    def get_feature_names_out(self, input_features=None):
        return np.array(list(self.names) if self.names else FEATURES)
