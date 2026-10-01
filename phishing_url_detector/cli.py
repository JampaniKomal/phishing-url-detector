"""The `phishing-url-detector` command."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__

DEFAULT_DATA = "data/urls.csv"
DEFAULT_MODELS = os.environ.get("PHISHING_URL_DETECTOR_MODELS", "models")


def _log(quiet: bool):
    return (lambda *_: None) if quiet else (lambda msg: print(msg, file=sys.stderr))


def cmd_train(a) -> int:
    from .model import save, train

    det = train(a.data, a.model, folds=a.folds, target_fpr=a.target_fpr, seed=a.seed, log=_log(a.quiet))
    _log(a.quiet)(f"model saved to {save(det, a.models)}")
    return 0


def _read_urls(a) -> list[str]:
    urls = list(a.urls)
    if a.file:
        text = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
        urls += [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return urls


def cmd_check(a) -> int:
    from .check import check
    from .model import load

    urls = _read_urls(a)
    if not urls:
        print("phishing-url-detector: give URLs as arguments or with --file", file=sys.stderr)
        return 2
    det = load(a.models)
    results = check(urls, det, threshold=a.threshold, lookalike_decides=not a.model_only)
    if a.json:
        print(
            json.dumps(
                {"model": det.meta["model"], "threshold": det.threshold, "results": [r.to_dict() for r in results]}, indent=2
            )
        )
    else:
        for r in results:
            p = f"{r.probability:.2f}" if r.probability is not None else "   -"
            print(f"{r.verdict.upper():<11} {p}  {r.url}")
            if a.details or len(results) == 1:
                for f in r.lookalike:
                    print(f"    imitates {f.brand} [{f.technique}, {f.severity}]: {f.detail}")
                for s in r.signals:
                    print(f"    - {s}")
    return 1 if any(r.verdict == "phishing" for r in results) else 0


def cmd_info(a) -> int:
    from .model import load

    det = load(a.models)
    m = det.meta
    cv = m["cv_by_site"]
    print(f"phishing-url-detector model: {m['model']} ({m['description']}), trained {m['created']}")
    print(f"  data: {m['data']['urls']} URLs from {m['data']['sites']} sites ({m['data']['path']})")
    print(f"  cross-validated by site: ROC-AUC {cv['at_0.5']['roc_auc']}, F1 {cv['at_0.5']['f1']} at 0.5")
    t = cv["at_threshold"]
    print(
        f"  threshold {det.threshold} (target {m['target_fpr']:.0%} false positives): recall {t['recall']:.1%}, false positives {t['false_positive_rate']:.1%}"
    )
    return 0


def cmd_serve(a) -> int:
    from .server import create_app

    app = create_app(a.models)
    print(f"Phishing URL Detector on http://{a.host}:{a.port}", file=sys.stderr)
    app.run(host=a.host, port=a.port, debug=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    from .model import MODELS

    p = argparse.ArgumentParser(prog="phishing-url-detector", description="Detect phishing URLs and lookalike domains.")
    p.add_argument("--version", action="version", version=f"phishing-url-detector {__version__}")
    p.add_argument("-q", "--quiet", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("train", help="train a model on labelled URLs")
    t.add_argument("--data", default=DEFAULT_DATA, help=f"CSV with url and status columns (default {DEFAULT_DATA})")
    t.add_argument("--model", choices=list(MODELS), default="combined")
    t.add_argument("--models", default=DEFAULT_MODELS, help="where to save it (default ./models)")
    t.add_argument("--folds", type=int, default=5)
    t.add_argument(
        "--target-fpr", type=float, default=0.02, help="false-positive rate the threshold is chosen for (default 0.02)"
    )
    t.add_argument("--seed", type=int, default=42)
    t.set_defaults(func=cmd_train)

    c = sub.add_parser("check", help="check URLs")
    c.add_argument("urls", nargs="*")
    c.add_argument("--file", help="a file with one URL per line ('-' for standard input)")
    c.add_argument("--models", default=DEFAULT_MODELS)
    c.add_argument("--json", action="store_true")
    c.add_argument("--details", action="store_true", help="findings and signals for every URL")
    c.add_argument("--threshold", type=float, help="probability at which a URL is phishing, instead of the model's")
    c.add_argument("--model-only", action="store_true", help="ignore lookalike findings in the verdict")
    c.set_defaults(func=cmd_check)

    i = sub.add_parser("info", help="show the trained model's metrics")
    i.add_argument("--models", default=DEFAULT_MODELS)
    i.set_defaults(func=cmd_info)

    s = sub.add_parser("serve", help="web page and JSON API on this machine")
    s.add_argument("--models", default=DEFAULT_MODELS)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as e:
        print(f"phishing-url-detector: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
