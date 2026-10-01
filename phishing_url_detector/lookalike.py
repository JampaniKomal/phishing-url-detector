"""Lookalike domains: the "imitate the look and feel of genuine domains" part of
SIH1454.

A URL is compared with the official domains of frequently impersonated brands,
global and Indian. The techniques recognised:

- homoglyph:     a label that reads as the brand once look-alike characters are
                 normalised (Cyrillic "а" for "a", "0" for "o", "rn" for "m", ...),
                 including internationalised (punycode) domains;
- typosquat:     one edit from a brand of six or more letters (two for nine or
                 more): paypa.com, paypall.com, pyapal.com;
- brand on an unofficial domain: paypal.example (medium: brands also own their name
                 under many country domains, like google.de);
- combosquat:    the brand plus other words: paypal-secure-login.com;
- brand in a subdomain: paypal.com.account-verify.example, paypal.blogspot.com;
- brand in the path of an unrelated site: example.com/paypal/login.

The brand's own domains never match. Short brand names (sbi, ups, dhl, jio) and
brands that are ordinary words (apple, chase, steam) are only matched as whole
words, because they appear inside many innocent names.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass

from .urlparts import URLParts

# brand label -> official registered domains
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "sharepoint.com", "outlook.com",
                  "office365.com", "azure.com", "msn.com", "bing.com", "skype.com", "xbox.com", "windows.net"),
    "office365": ("office.com", "office365.com", "microsoft.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com", "office.com", "microsoft.com"),
    "onedrive": ("onedrive.com", "live.com", "microsoft.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "google": ("google.com", "google.co.in", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com",
               "appspot.com", "blogspot.com", "goo.gl", "g.co"),
    "gmail": ("gmail.com", "google.com"),
    "youtube": ("youtube.com", "youtu.be", "google.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.ca", "amazon.fr",
               "amazonaws.com", "amazon.jobs", "a.co"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com", "messenger.com", "fb.me"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "dropbox": ("dropbox.com", "db.tt"),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",),
    "yahoo": ("yahoo.com", "yahoo.co.jp"),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "citibank": ("citibank.com", "citi.com"),
    "hsbc": ("hsbc.com", "hsbc.co.uk", "hsbc.co.in"),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "ebay": ("ebay.com", "ebay.co.uk", "ebay.de", "ebay.in"),
    "spotify": ("spotify.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "github": ("github.com", "github.io"),
    # India
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"),
    "onlinesbi": ("onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"),
    "hdfcbank": ("hdfcbank.com",),
    "icicibank": ("icicibank.com",),
    "axisbank": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "pnbindia": ("pnbindia.in",),
    "bankofbaroda": ("bankofbaroda.in", "bankofbaroda.com"),
    "paytm": ("paytm.com", "paytm.in", "paytmbank.com"),
    "phonepe": ("phonepe.com",),
    "irctc": ("irctc.co.in",),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in", "incometaxindia.gov.in"),
    "epfindia": ("epfindia.gov.in",),
    "indiapost": ("indiapost.gov.in",),
    "flipkart": ("flipkart.com",),
    "airtel": ("airtel.in", "airtel.com"),
    "jio": ("jio.com",),
}  # fmt: skip
OFFICIAL = frozenset(d for domains in BRANDS.values() for d in domains)
# Official domains where anyone can publish under a subdomain: being on one proves
# nothing about who runs the page, so their subdomains and paths are still checked.
MULTI_TENANT = frozenset({"blogspot.com", "appspot.com", "googleusercontent.com", "sharepoint.com", "github.io",
                          "windows.net", "amazonaws.com"})  # fmt: skip
# Brands that are also ordinary words or common word parts ("chase" in "purchase",
# "apple" in "pineapple"): only matched as separate words, never inside one.
WORD_ONLY = frozenset(
    {"apple", "chase", "steam", "adobe", "outlook", "office365", "ups", "usps", "dhl", "jio", "sbi", "kotak", "icloud"}
)

# Characters that render like ASCII letters. Not exhaustive (Unicode's confusables
# list has thousands); these are the ones seen in phishing domains.
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ѕ": "s",
    "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ɑ": "a", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i",
    "κ": "k", "τ": "t", "υ": "u", "ѵ": "v", "ı": "i", "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "|": "l",
})  # fmt: skip
_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))

SEVERITY = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    brand: str
    technique: str
    severity: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def skeletons(label: str) -> set[str]:
    """Ways a label can read once look-alike characters are normalised."""
    base = unicodedata.normalize("NFKD", label.lower())
    base = "".join(c for c in base if not unicodedata.combining(c)).translate(_CONFUSABLE)
    out = {base, base.replace("l", "i")}
    for a, b in _SEQUENCES:
        out |= {s.replace(a, b) for s in list(out)}
    return out


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein distance (optimal string alignment), capped at limit."""
    if abs(len(a) - len(b)) >= limit:
        return limit
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return min(prev[-1], limit)


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[^a-z]+", text.lower()) if w]


def find(p: URLParts) -> list[Finding]:
    tenant = p.registered in MULTI_TENANT
    if p.is_ip or not p.domain or (p.registered in OFFICIAL and not tenant):
        return []
    if p.suffix in BRANDS:
        return []  # a brand's own top-level domain (.microsoft, .google, .sbi) is only open to the brand
    label = p.domain
    unicode_label = p.unicode_host.split(".")[-len(p.suffix.split(".")) - 1] if p.suffix else label
    shapes = skeletons(unicode_label) | skeletons(label)
    label_words = _words(unicode_label)
    sub_words = _words(p.subdomain)
    path_words = _words(p.path + " " + p.query)
    findings: dict[str, Finding] = {}

    def add(f: Finding) -> None:
        old = findings.get(f.brand)
        if old is None or SEVERITY[f.severity] > SEVERITY[old.severity]:
            findings[f.brand] = f

    for brand, official in BRANDS.items():
        short = len(brand) <= 4
        home = official[0]
        if tenant:
            pass  # the label is the platform's own name
        elif label == brand:
            add(
                Finding(
                    brand,
                    "unofficial-domain",
                    "medium",
                    f"'{p.registered}' is the brand name on a domain not in the official list ({home}); "
                    "brands often own their name under many country domains",
                )
            )
        elif brand in shapes and unicode_label != brand:
            kind = "internationalised (punycode) " if p.host != p.unicode_host else ""
            add(Finding(brand, "homoglyph", "high", f"'{p.unicode_host}' is a {kind}look-alike of {home}"))
        elif len(brand) >= 6 and brand not in WORD_ONLY and edit_distance(label, brand) <= (2 if len(brand) >= 9 else 1):
            add(Finding(brand, "typosquat", "high", f"'{p.registered}' is a misspelling of {home}"))
        elif brand in label_words and len(label_words) > 1:
            add(Finding(brand, "combosquat", "medium", f"'{p.registered}' combines the brand '{brand}' with other words"))
        elif brand not in WORD_ONLY and not short and (label.startswith(brand) or label.endswith(brand)):
            add(Finding(brand, "combosquat", "low", f"'{p.registered}' starts or ends with the brand '{brand}'"))

        if brand in sub_words:
            official_inside = any(f"{d}." in f"{p.subdomain}." for d in official)
            sev, how = ("high", f"'{home}' placed in front of another domain, '{p.registered}'") if official_inside else (
                "medium", f"the subdomain '{p.subdomain}' names {brand}, but the site is '{p.registered}'")  # fmt: skip
            add(Finding(brand, "brand-in-subdomain", sev, how))
        elif not short and brand in path_words:
            add(Finding(brand, "brand-in-path", "low", f"the path mentions {brand} on an unrelated site, '{p.registered}'"))

    return sorted(findings.values(), key=lambda f: -SEVERITY[f.severity])


def strongest(findings: list[Finding]) -> int:
    return max((SEVERITY[f.severity] for f in findings), default=0)
