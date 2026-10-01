"""Models, evaluation and model files.

Every model is a scikit-learn pipeline from raw URL strings to a probability of
phishing, so training, evaluation and checking all use the same code.

Evaluation groups URLs by registered domain: every URL of a site is either in
training or in testing, never both. Half the dataset's URLs share a site with
another URL (one site has 351), so a random split lets a model recognise sites
instead of phishing; the benchmark reports both.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from . import __version__
from .features import FEATURES, URLFeatures, v1_features
from .urlparts import parse

MODELS = {
    "v1": "v1's 13 features (as in the notebooks) and a Random Forest",
    "features": "v2's URL features and gradient-boosted trees",
    "ngrams": "character n-grams (TF-IDF) and logistic regression",
    "combined": "average of the features and ngrams models (default)",
}


class V1Features(URLFeatures):
    def transform(self, X):
        return np.array([list(v1_features(u).values()) for u in X], dtype=float)


def build(kind: str, seed: int = 42):
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier, VotingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline

    if kind == "v1":
        return make_pipeline(V1Features(), RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=-1))
    features = make_pipeline(
        URLFeatures(tuple(FEATURES)),
        HistGradientBoostingClassifier(max_iter=400, learning_rate=0.06, random_state=seed),
    )
    ngrams = make_pipeline(
        TfidfVectorizer(analyzer="char", ngram_range=(3, 5), lowercase=True, sublinear_tf=True, min_df=2, max_features=200_000),
        LogisticRegression(C=4.0, max_iter=2000),
    )
    if kind == "features":
        return features
    if kind == "ngrams":
        return ngrams
    if kind == "combined":
        return VotingClassifier([("features", features), ("ngrams", ngrams)], voting="soft")
    raise ValueError(f"unknown model {kind!r}; choose from {', '.join(MODELS)}")


def load_data(path: str | Path) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """URLs, labels (1 = phishing) and each URL's registered domain."""
    df = pd.read_csv(path)
    df = df.drop_duplicates("url")
    urls = df["url"].astype(str).to_numpy()
    y = (df["status"] == "phishing").astype(int).to_numpy()
    groups = np.array([parse(u).registered or u for u in urls])
    return urls, y, groups


def _metrics(y: np.ndarray, p: np.ndarray, t: float = 0.5) -> dict:
    from sklearn.metrics import roc_auc_score

    pred = p >= t
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "roc_auc": round(float(roc_auc_score(y, p)), 4),
        "accuracy": round((tp + tn) / len(y), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / max(precision + recall, 1e-9), 4),
        "false_positive_rate": round(fp / max(fp + tn, 1), 4),
    }


def cross_validate(kind: str, urls, y, groups, folds: int = 5, grouped: bool = True, seed: int = 42, log=print) -> dict:
    """Out-of-fold probabilities and metrics for one model."""
    from sklearn.model_selection import GroupKFold, StratifiedKFold

    splitter = (
        GroupKFold(folds, shuffle=True, random_state=seed) if grouped else StratifiedKFold(folds, shuffle=True, random_state=seed)
    )
    oof = np.zeros(len(y))
    start = time.time()
    for i, (tr, te) in enumerate(splitter.split(urls, y, groups)):
        model = build(kind, seed).fit(urls[tr], y[tr])
        oof[te] = model.predict_proba(urls[te])[:, 1]
        log(f"  {kind} fold {i + 1}/{folds}")
    return {"oof": oof, "metrics": _metrics(y, oof), "seconds": round(time.time() - start, 1)}


def threshold_for_fpr(benign_scores: np.ndarray, target: float) -> float:
    """The lowest threshold (at least 0.5) at which at most `target` of benign
    scores reach it, rounded up so rounding never lets one through."""
    import math

    s = np.sort(np.asarray(benign_scores, dtype=float))[::-1]
    allowed = int(np.floor(target * len(s)))
    if allowed >= len(s):
        return 0.5
    return max(0.5, min(math.ceil(float(np.nextafter(s[allowed], np.inf)) * 10_000) / 10_000, 1.0))


@dataclass
class Detector:
    pipeline: object
    meta: dict

    @property
    def threshold(self) -> float:
        return self.meta["threshold"]

    def score(self, urls: list[str]) -> np.ndarray:
        return self.pipeline.predict_proba(np.asarray(urls, dtype=object))[:, 1]


def train(
    data: str | Path, kind: str = "combined", folds: int = 5, target_fpr: float = 0.02, seed: int = 42, log=print
) -> Detector:
    import sklearn

    urls, y, groups = load_data(data)
    log(f"{len(urls)} URLs ({int(y.sum())} phishing) from {len(set(groups))} sites; cross-validating by site")
    cv = cross_validate(kind, urls, y, groups, folds, grouped=True, seed=seed, log=log)
    threshold = threshold_for_fpr(cv["oof"][y == 0], target_fpr)
    log(f"threshold {threshold} for a {target_fpr:.0%} false-positive rate; training on everything")
    pipeline = build(kind, seed).fit(urls, y)
    meta = {
        "phishing_url_detector_version": __version__,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sklearn_version": sklearn.__version__,
        "model": kind,
        "description": MODELS[kind],
        "threshold": threshold,
        "target_fpr": target_fpr,
        "data": {"path": str(data), "urls": len(urls), "phishing": int(y.sum()), "sites": len(set(groups))},
        "cv_by_site": {"at_0.5": cv["metrics"], "at_threshold": _metrics(y, cv["oof"], threshold)},
    }
    m = meta["cv_by_site"]["at_threshold"]
    log(
        f"cross-validated by site: ROC-AUC {m['roc_auc']}; at {threshold}: recall {m['recall']:.1%}, false positives {m['false_positive_rate']:.1%}"
    )
    return Detector(pipeline, meta)


def save(det: Detector, directory: str | Path) -> Path:
    import hashlib

    import joblib

    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump(det.pipeline, d / "model.joblib", compress=3)
    det.meta["model_sha256"] = hashlib.sha256((d / "model.joblib").read_bytes()).hexdigest()
    (d / "model.json").write_text(json.dumps(det.meta, indent=2), encoding="utf-8")
    return d


def load(directory: str | Path) -> Detector:
    import hashlib

    import joblib

    d = Path(directory)
    if not (d / "model.json").exists() or not (d / "model.joblib").exists():
        raise FileNotFoundError(f"no trained model in {d} (run `phishing-url-detector train`)")
    meta = json.loads((d / "model.json").read_text(encoding="utf-8"))
    if hashlib.sha256((d / "model.joblib").read_bytes()).hexdigest() != meta.get("model_sha256"):
        raise ValueError(f"{d / 'model.joblib'} does not match the hash in model.json; retrain instead of loading it")
    return Detector(joblib.load(d / "model.joblib"), meta)
