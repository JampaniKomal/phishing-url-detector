"""URL parsing, lookalike detection and features."""

import pytest

from phishing_url_detector import features, lookalike
from phishing_url_detector.urlparts import parse


def test_parse_parts():
    p = parse("HTTPS://Login.Example.co.uk:8443/a/b?x=1")
    assert (p.scheme, p.host, p.port, p.path, p.query) == ("https", "login.example.co.uk", 8443, "/a/b", "x=1")
    assert (p.subdomain, p.domain, p.suffix, p.registered) == ("login", "example", "co.uk", "example.co.uk")
    assert parse("example.com/path").host == "example.com"  # no scheme
    assert parse("http://paypal.com.account-verify.example/").registered == "account-verify.example"  # unlisted TLD
    assert parse("http://192.168.10.5/login").is_ip
    assert parse("http://0x7f.0x0.0x0.0x1/").is_ip
    idn = parse("https://xn--pypal-4ve.com/")
    assert idn.unicode_host == "pаypal.com" and idn.domain == "xn--pypal-4ve"


def techniques(url: str) -> dict[str, tuple[str, str]]:
    return {f.brand: (f.technique, f.severity) for f in lookalike.find(parse(url))}


@pytest.mark.parametrize(
    "url, brand, technique, severity",
    [
        ("http://paypa1.com/login", "paypal", "homoglyph", "high"),
        ("https://xn--pypal-4ve.com/", "paypal", "homoglyph", "high"),  # Cyrillic а
        ("http://rnicrosoft.com/", "microsoft", "homoglyph", "high"),
        ("http://paypall.com/", "paypal", "typosquat", "high"),
        ("http://micorsoft.com/", "microsoft", "typosquat", "high"),
        ("http://paypal.example/", "paypal", "unofficial-domain", "medium"),
        ("http://icl0ud.com/", "icloud", "homoglyph", "high"),
        ("http://paypal-secure-login.com/", "paypal", "combosquat", "medium"),
        ("http://sbi-kyc-update.in/", "sbi", "combosquat", "medium"),
        ("http://netflixbilling.net/", "netflix", "combosquat", "low"),
        ("http://paypal.com.account-verify.example/x", "paypal", "brand-in-subdomain", "high"),
        ("http://paypal.blogspot.com/", "paypal", "brand-in-subdomain", "medium"),
        ("http://evil.example/paypal/login", "paypal", "brand-in-path", "low"),
    ],
)
def test_lookalike_techniques(url, brand, technique, severity):
    assert techniques(url)[brand] == (technique, severity)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com/signin",
        "https://onlinesbi.sbi/",
        "https://login.microsoftonline.com/",
        "https://www.purchase.com/",  # contains "chase"
        "https://pineapple.com/",  # contains "apple"
        "https://stream.com/",  # one edit from "steam", a word-only brand
        "https://groups.example/",  # contains "ups"
        "https://cloud.microsoft/",  # Microsoft's own top-level domain
        "https://hicloud.com/",  # one letter from "icloud", a word-only brand
        "http://192.168.1.1/login",
    ],
)
def test_no_lookalike_findings(url):
    assert lookalike.find(parse(url)) == []


def test_edit_distance():
    assert lookalike.edit_distance("paypal", "paypal") == 0
    assert lookalike.edit_distance("pyapal", "paypal") == 1  # transposition counts once
    assert lookalike.edit_distance("paypa", "paypal") == 1
    assert lookalike.edit_distance("abc", "xyzxyz") == 3  # capped


def test_v1_features_reproduce_the_notebook_including_its_bugs():
    f = features.v1_features("http://192.168.0.1/login?a=b")
    assert f["url_length"] == 28 and f["path_length"] == 6 and f["count_equals"] == 1
    assert f["has_ip"] == 0  # the notebook's IPv4 pattern needs a "/" inside the host name
    assert features.v1_features("https://www.microsoft.com/")["is_shortened"] == 1  # "t.co" in "microsoft.com"


def test_v2_features_fix_them():
    assert features.extract("http://192.168.0.1/login")["is_ip_host"] == 1
    assert features.extract("https://www.microsoft.com/")["is_shortener"] == 0
    assert features.extract("https://bit.ly/abc")["is_shortener"] == 1
    f = features.extract("http://paypal.com.secure-login.000webhostapp.com/verify/account.php?user=a@b.com")
    assert f["free_hosting"] == 1 and f["lookalike_severity"] == 3 and f["email_in_url"] == 1
    assert f["sensitive_words"] >= 3 and f["php_or_html"] == 1  # the path ends in .php; the query is separate
    assert features.extract("https://www.paypal.com/")["official_brand_domain"] == 1
    assert list(features.extract("x.com")) == features.FEATURES
