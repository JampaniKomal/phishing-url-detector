"""Reproduces docs/BENCHMARK.md.

1. Every model, cross-validated with URLs grouped by site (registered domain),
   and v1 and the default model with a plain random split for comparison.
2. Models trained on the whole 2020 dataset, then tested on today's phishing
   (the OpenPhish community feed) and on the home pages of the most popular
   sites (the Tranco list).
3. The lookalike checks alone: generated look-alikes of every brand's domain,
   and the Tranco sites as false-alarm test.

The feeds are downloaded when the script runs and not stored; results record
their date and size. Nothing is ever visited: URLs are only parsed as text.

    python scripts/benchmark.py > docs/benchmark/results.json
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

import numpy as np

from phishing_url_detector import lookalike
from phishing_url_detector.model import _metrics, build, cross_validate, load_data, threshold_for_fpr
from phishing_url_detector.urlparts import parse

ROOT = Path(__file__).resolve().parents[1]
OPENPHISH = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_ID = "https://tranco-list.eu/top-1m-id"


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "phishing-url-detector-benchmark"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def lookalikes(brand: str, home: str) -> dict[str, list[str]]:
    """Generated look-alike domains per technique, like dnstwist's permutations."""
    label, suffix = home.split(".", 1)
    out: dict[str, list[str]] = {k: [] for k in ("omission", "repetition", "transposition", "replacement",
                                                 "homoglyph", "hyphenation", "combosquat", "subdomain", "tld-swap")}  # fmt: skip
    for i in range(len(label)):
        out["omission"].append(label[:i] + label[i + 1 :])
        out["repetition"].append(label[:i] + label[i] + label[i:])
        if i < len(label) - 1:
            out["transposition"].append(label[:i] + label[i + 1] + label[i] + label[i + 2 :])
            out["hyphenation"].append(label[: i + 1] + "-" + label[i + 1 :])
        for c in "aeiou":
            if c != label[i]:
                out["replacement"].append(label[:i] + c + label[i + 1 :])
    glyphs = {
        "o": ["0", "о"],
        "l": ["1"],
        "i": ["1", "і"],
        "a": ["а"],
        "e": ["е", "3"],
        "m": ["rn"],
        "w": ["vv"],
        "c": ["с"],
        "p": ["р"],
    }
    for i, ch in enumerate(label):
        for g in glyphs.get(ch, []):
            out["homoglyph"].append(label[:i] + g + label[i + 1 :])
    for w in ("login", "secure", "verify", "account", "support", "update"):
        out["combosquat"] += [f"{label}-{w}", f"{w}-{label}", f"{label}{w}"]
    out["subdomain"] = [f"{home}.account-verify", f"{label}.secure-login"]
    out["tld-swap"] = [label]
    result = {}
    for k, labels in out.items():
        if k == "subdomain":
            result[k] = [f"https://{x}.com/signin" for x in labels]
        elif k == "tld-swap":
            result[k] = [
                f"https://{label}.{t}/" for t in ("xyz", "top", "info", "online") if f"{label}.{t}" not in lookalike.OFFICIAL
            ]
        else:
            hosts = []
            for x in sorted(set(labels)):
                if x == label or len(x) < 2:
                    continue
                if any(ord(c) > 127 for c in x):
                    x = x.encode("idna").decode("ascii")
                hosts.append(f"https://{x}.{suffix}/")
            result[k] = [h for h in hosts if parse(h).registered not in lookalike.OFFICIAL]
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=ROOT / "data" / "urls.csv", type=Path)
    ap.add_argument("--tranco-top", type=int, default=10_000)
    args = ap.parse_args()
    urls, y, groups = load_data(args.data)
    result: dict = {"data": {"urls": len(urls), "phishing": int(y.sum()), "sites": len(set(groups))}}
    counts = np.unique(groups, return_counts=True)[1]
    result["data"]["urls_sharing_a_site"] = round(float(counts[counts > 1].sum() / len(urls)), 4)

    log("cross-validation")
    cv = {}
    for kind in ("v1", "features", "ngrams", "combined"):
        cv[f"{kind}_by_site"] = cross_validate(kind, urls, y, groups, grouped=True, log=log)
    for kind in ("v1", "combined"):
        cv[f"{kind}_random"] = cross_validate(kind, urls, y, groups, grouped=False, log=log)
    t = threshold_for_fpr(cv["combined_by_site"]["oof"][y == 0], 0.02)
    result["cross_validation"] = {k: {"metrics": v["metrics"], "seconds": v["seconds"]} for k, v in cv.items()}
    result["combined_threshold_2pct_fpr"] = t
    result["combined_by_site_at_threshold"] = _metrics(y, cv["combined_by_site"]["oof"], t)

    log("training on everything for the out-of-time tests")
    models = {k: build(k).fit(urls, y) for k in ("v1", "combined")}

    feed = [u.strip() for u in fetch(OPENPHISH).decode("utf-8", "replace").splitlines() if u.strip()]
    tranco_id = fetch(TRANCO_ID).decode().strip()
    with zipfile.ZipFile(io.BytesIO(fetch(TRANCO))) as z:
        lines = z.read(z.namelist()[0]).decode().splitlines()[: args.tranco_top]
    tranco = [f"https://{line.split(',')[1]}/" for line in lines]
    result["sources"] = {"openphish_urls": len(feed), "fetched": time.strftime("%Y-%m-%d"),
                         "tranco_list_id": tranco_id, "tranco_top": len(tranco)}  # fmt: skip
    ood = {}
    for name, m in models.items():
        p_feed = m.predict_proba(np.array(feed, dtype=object))[:, 1]
        p_tr = m.predict_proba(np.array(tranco, dtype=object))[:, 1]
        row = {"openphish_detected_at_0.5": round(float((p_feed >= 0.5).mean()), 4),
               "tranco_flagged_at_0.5": round(float((p_tr >= 0.5).mean()), 4)}  # fmt: skip
        if name == "combined":
            row[f"openphish_detected_at_{t}"] = round(float((p_feed >= t).mean()), 4)
            row[f"tranco_flagged_at_{t}"] = round(float((p_tr >= t).mean()), 4)
            with_look = (p_feed >= t) | np.array([lookalike.strongest(lookalike.find(parse(u))) == 3 for u in feed])
            row["openphish_detected_model_or_high_lookalike"] = round(float(with_look.mean()), 4)
            oof = cv["combined_by_site"]["oof"]
            row["sweep"] = [
                {
                    "threshold": th,
                    "dataset_recall": round(float((oof[y == 1] >= th).mean()), 4),
                    "dataset_false_positives": round(float((oof[y == 0] >= th).mean()), 4),
                    "openphish_detected": round(float((p_feed >= th).mean()), 4),
                    "tranco_flagged": round(float((p_tr >= th).mean()), 4),
                }
                for th in (0.5, 0.55, 0.6, 0.65, 0.7, t, 0.8, 0.9)
            ]
            row["tranco_top_flagged_examples"] = [(tranco[i], round(float(p_tr[i]), 3)) for i in np.argsort(-p_tr)[:10]]
        ood[name] = row
    result["out_of_time"] = ood
    feed_look = [lookalike.find(parse(u)) for u in feed]
    result["openphish_lookalike"] = {
        "examples": [(u, f[0].brand, f[0].technique, f[0].severity) for u, f in zip(feed, feed_look, strict=True) if f][:15],
        "any": round(float(np.mean([bool(f) for f in feed_look])), 4),
        "high": round(float(np.mean([lookalike.strongest(f) == 3 for f in feed_look])), 4),
    }

    log("lookalike checks")
    per_tech: dict[str, dict[str, list[int]]] = {"distinctive": {}, "word-only or 5 letters": {}}
    for brand, official in lookalike.BRANDS.items():
        if len(brand) < 5:
            continue
        group = "word-only or 5 letters" if brand in lookalike.WORD_ONLY or len(brand) == 5 else "distinctive"
        for tech, gen in lookalikes(brand, official[0]).items():
            for u in gen:
                hit = any(f.brand == brand for f in lookalike.find(parse(u)))
                per_tech[group].setdefault(tech, []).append(int(hit))
    tranco_findings = [(u, lookalike.find(parse(u))) for u in tranco]
    flagged = [(u, f) for u, f in tranco_findings if f]
    high = [(u, f) for u, f in flagged if lookalike.strongest(f) == 3]
    result["lookalike"] = {
        "generated_detected": {
            g: {k: {"n": len(v), "detected": round(float(np.mean(v)), 4)} for k, v in techs.items()}
            for g, techs in per_tech.items()
        },
        "tranco_flagged_any": round(len(flagged) / len(tranco), 4),
        "tranco_flagged_high": round(len(high) / len(tranco), 4),
        "tranco_high_examples": [(u, f[0].brand, f[0].technique) for u, f in high[:25]],
        "tranco_any_examples": [(u, f[0].brand, f[0].technique, f[0].severity) for u, f in flagged[:25]],
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
