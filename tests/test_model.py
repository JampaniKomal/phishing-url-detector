"""Training, model files, the CLI and the web server, on a sample of the real data."""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from phishing_url_detector import model
from phishing_url_detector.cli import main

DATA = Path(__file__).resolve().parents[1] / "data" / "urls.csv"


def test_dataset_is_what_the_docs_say():
    df = pd.read_csv(DATA)
    assert list(df.columns) == ["url", "status"]
    assert len(df) == 11430 and (df.status == "phishing").sum() == 5715
    urls, y, groups = model.load_data(DATA)
    assert len(urls) == len(y) == len(groups) == 11429  # one duplicate URL
    counts = np.unique(groups, return_counts=True)[1]
    assert counts.max() > 300  # one site has hundreds of URLs: why evaluation groups by site


def test_threshold_for_fpr():
    benign = np.linspace(0, 1, 101)
    t = model.threshold_for_fpr(benign, 0.05)
    assert (benign >= t).mean() <= 0.05 < (benign >= t - 0.011).mean()


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("m")
    sample = pd.read_csv(DATA).sample(2500, random_state=0)
    sample.to_csv(tmp / "sample.csv", index=False)
    assert main(["-q", "train", "--data", str(tmp / "sample.csv"), "--models", str(tmp / "models"), "--folds", "3"]) == 0
    return tmp / "models"


def test_trained_model(trained):
    meta = json.loads((trained / "model.json").read_text())
    assert meta["model"] == "combined" and 0.5 <= meta["threshold"] <= 1
    assert meta["cv_by_site"]["at_0.5"]["roc_auc"] > 0.85
    det = model.load(trained)
    p = det.score(["http://paypal.com.account-verify.example/login.php", "https://en.wikipedia.org/wiki/Phishing"])
    assert p[0] > p[1]


def test_tampered_model_is_refused(trained, tmp_path):
    for f in ("model.json", "model.joblib"):
        (tmp_path / f).write_bytes((trained / f).read_bytes())
    with open(tmp_path / "model.joblib", "ab") as f:
        f.write(b"\0")
    with pytest.raises(ValueError, match="does not match"):
        model.load(tmp_path)


def test_cli_check(trained, tmp_path, capsys):
    code = main(["check", "http://paypa1.com/signin", "--models", str(trained)])
    out = capsys.readouterr().out
    assert code == 1 and out.startswith("PHISHING") and "imitates paypal [homoglyph" in out
    (tmp_path / "list.txt").write_text("# a comment\nhttps://www.wikipedia.org/\n\n", encoding="utf-8")
    assert main(["check", "--file", str(tmp_path / "list.txt"), "--models", str(trained), "--json", "--threshold", "0.999"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [r["url"] for r in report["results"]] == ["https://www.wikipedia.org/"]
    assert main(["check", "--models", str(trained)]) == 2  # nothing to check
    assert main(["info", "--models", str(trained)]) == 0


def test_web_server(trained):
    from phishing_url_detector.server import create_app

    client = create_app(str(trained)).test_client()
    assert b"Phishing URL Detector" in client.get("/").data
    r = client.post("/api/check", json={"urls": ["http://paypal.com.account-verify.example/", "not a url at all"]}).get_json()
    assert r["results"][0]["verdict"] == "phishing"
    assert r["results"][0]["lookalike"][0]["technique"] == "brand-in-subdomain"
    assert client.get("/api/check").status_code == 400
    page = client.post("/", data={"urls": "http://<script>alert(1)</script>.example/"}).data
    assert b"<script>alert" not in page  # escaped, never rendered as HTML
