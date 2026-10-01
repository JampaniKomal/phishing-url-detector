"""Checking URLs: the model's score, lookalike findings and plain-language signals."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import features, lookalike
from .model import Detector
from .urlparts import parse


@dataclass
class Result:
    url: str
    verdict: str  # phishing, legitimate, invalid
    probability: float | None = None
    threshold: float | None = None
    site: str = ""
    lookalike: list[lookalike.Finding] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["lookalike"] = [f.to_dict() for f in self.lookalike]
        return d


def signals(url: str) -> list[str]:
    """Human-readable red flags in the URL itself (they explain, they don't decide)."""
    p = parse(url)
    f = features.extract(url)
    out = []
    if p.is_ip:
        out.append("the host is an IP address, not a domain name")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        out.append("an '@' in the address: browsers ignore everything before it")
    if f["is_punycode"]:
        out.append(f"internationalised domain name, displayed as '{p.unicode_host}'")
    if f["is_shortener"]:
        out.append("a link shortener hides the real destination")
    if f["free_hosting"]:
        out.append(f"hosted on a platform where anyone can publish ({p.registered})")
    if f["subdomain_levels"] >= 3:
        out.append(f"{int(f['subdomain_levels'])} levels of subdomain in front of '{p.registered}'")
    if f["has_port"]:
        out.append(f"a non-standard port ({p.port})")
    if f["sensitive_words"] >= 2:
        out.append("several account/security words (login, verify, secure, ...)")
    if f["email_in_url"]:
        out.append("an email address inside the URL, typical of targeted phishing links")
    if f["url_length"] > 100:
        out.append(f"a very long URL ({int(f['url_length'])} characters)")
    if p.scheme == "http":
        out.append("no HTTPS")
    return out


def check(urls: list[str], det: Detector, threshold: float | None = None, lookalike_decides: bool = True) -> list[Result]:
    """Score URLs. A URL is phishing when the model's probability reaches the
    threshold, or, with lookalike_decides, when it imitates a brand's domain in
    a way that is rarely innocent (a high-severity lookalike finding)."""
    t = det.threshold if threshold is None else threshold
    results: list[Result] = []
    valid = []
    for u in urls:
        u = u.strip()
        p = parse(u) if u else None
        if not u or p is None or not p.host:
            results.append(Result(u, "invalid"))
        else:
            results.append(Result(u, "", site=p.registered, lookalike=lookalike.find(p), signals=signals(u)))
            valid.append(len(results) - 1)
    if valid:
        scores = det.score([results[i].url for i in valid])
        for i, s in zip(valid, scores, strict=True):
            r = results[i]
            r.probability, r.threshold = round(float(s), 4), t
            high = lookalike.strongest(r.lookalike) == 3
            r.verdict = "phishing" if s >= t or (lookalike_decides and high) else "legitimate"
    return results
