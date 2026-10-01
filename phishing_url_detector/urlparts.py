"""Splitting a URL into the parts phishing detection cares about.

The registered domain (what someone actually bought, e.g. "example.co.uk") comes
from the Public Suffix List snapshot bundled with tldextract, so parsing never
touches the network.
"""

from __future__ import annotations

import contextlib
import ipaddress
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


@dataclass(frozen=True)
class URLParts:
    url: str
    scheme: str
    host: str  # lower-case, as written (punycode stays punycode)
    unicode_host: str  # punycode labels decoded, for display and homoglyph checks
    port: int | None
    path: str
    query: str
    subdomain: str
    domain: str  # the label before the public suffix: "paypal" in "www.paypal.co.uk"
    suffix: str
    registered: str  # domain + suffix: "paypal.co.uk"
    is_ip: bool


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # 0x7f.1, 3232235777 and other forms browsers still accept
    parts = host.split(".")
    return 1 <= len(parts) <= 4 and all(p and (p.isdigit() or p.lower().startswith("0x")) for p in parts)


def _decode(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError):
                label = label.encode("ascii").decode("idna")
        labels.append(label)
    return unicodedata.normalize("NFKC", ".".join(labels))


@lru_cache(maxsize=65536)
def parse(url: str) -> URLParts:
    raw = url.strip()
    if "://" not in raw[:16]:
        raw = "http://" + raw
    s = urlsplit(raw)
    host = (s.hostname or "").rstrip(".").lower()
    try:
        port = s.port
    except ValueError:
        port = None
    is_ip = _is_ip(host)
    if is_ip or not host:
        sub, dom, suf, reg = "", host, "", host
    else:
        e = _EXTRACT(host)
        sub, dom, suf = e.subdomain, e.domain, e.suffix
        if not suf and "." in host:
            # a top-level domain the Public Suffix List doesn't know (.example, .internal): treat the last label as it
            *rest, dom, suf = host.split(".")
            sub = ".".join(rest)
        reg = f"{dom}.{suf}" if dom and suf else host
    return URLParts(
        url=url,
        scheme=s.scheme.lower(),
        host=host,
        unicode_host=_decode(host),
        port=port,
        path=s.path,
        query=s.query,
        subdomain=sub,
        domain=dom,
        suffix=suf,
        registered=reg,
        is_ip=is_ip,
    )
