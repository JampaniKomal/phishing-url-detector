# AI-Powered Phishing URL Detector

[![CI](https://github.com/JampaniKomal/phishing-url-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/JampaniKomal/phishing-url-detector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Detects phishing URLs from the URL alone, and catches domains built to imitate
genuine ones: `paypa1.com`, `pаypal.com` with a Cyrillic "а",
`paypal.com.account-verify.example`, `sbi-kyc-update.in`. It is a machine-learning
model plus a lookalike-domain checker, usable from the command line, a small
web page, a JSON API, or the original step-by-step notebooks.

```
$ phishing-url-detector check "http://paypal.com.account-verify.example/login.php"
PHISHING    1.00  http://paypal.com.account-verify.example/login.php
    imitates paypal [brand-in-subdomain, high]: 'paypal.com' placed in front of another domain, 'account-verify.example'
    - several account/security words (login, verify, secure, ...)
    - no HTTPS
```

Nothing is ever opened or downloaded: URLs are only analysed as text.

## Inspiration

Inspired by a real-world cybersecurity challenge from the Smart India Hackathon (SIH).

- **Organization:** National Technical Research Organisation (NTRO)
- **Problem Statement ID:** SIH1454
- **Title:** Create an intelligent system using AI/ML to detect phishing domains which imitate look and feel of genuine domains.

## Quick start

```bash
git clone https://github.com/JampaniKomal/phishing-url-detector.git
cd phishing-url-detector
pip install -e .
phishing-url-detector train          # about a minute; the data is included
phishing-url-detector check "http://paypa1.com/signin" "https://en.wikipedia.org/wiki/Phishing"
```

More:

```bash
phishing-url-detector check --file urls.txt --details   # one URL per line; findings for every URL
phishing-url-detector check --file - --json < urls.txt  # JSON to standard output
phishing-url-detector info                              # the model's cross-validated metrics
phishing-url-detector serve                             # web page and API on http://127.0.0.1:5000
```

`check` exits with 1 when any URL is phishing, so it can gate a script. The
API takes `GET /api/check?url=...` or `POST /api/check` with
`{"urls": [...]}`. With Docker:

```bash
docker build -t phishing-url-detector .
docker run --rm phishing-url-detector check "http://paypa1.com/signin"
docker run --rm -p 127.0.0.1:5000:5000 phishing-url-detector serve --host 0.0.0.0
```

## How it works

A URL is **phishing** when the model's probability reaches its threshold, or
when it imitates a brand's domain in a way that is rarely innocent (a
high-severity lookalike finding). The output also lists the lookalike findings
and plain-language signals, such as an IP address instead of a domain name, a
link shortener, or free hosting, so a person can see why.

**The model** (`--model combined`, the default) averages two models:

- gradient-boosted trees on 41 URL features: lengths and counts, host
  structure (subdomain depth, hyphens, digits, entropy), IP-address hosts,
  ports, internationalised names, link shorteners, free-hosting platforms,
  sensitive words (login, verify, secure, ...), an email address in the URL,
  and the lookalike checks below;
- logistic regression on character 3- to 5-grams of the whole URL (TF-IDF),
  which picks up patterns no hand-made feature names.

Its threshold is set so that at most 2% of legitimate URLs reach it in
cross-validation.

**The lookalike checks** compare the URL's registered domain with the official
domains of 57 frequently impersonated brand names, including Indian ones
(SBI, HDFC Bank, ICICI Bank, Paytm, IRCTC, UIDAI, Income Tax):

| Technique | Example | Severity |
|---|---|---|
| Homoglyph (look-alike characters, punycode) | `paypa1.com`, `xn--pypal-4ve.com` (pаypal.com), `rnicrosoft.com` | high |
| Typosquat (one edit, two for long names) | `paypall.com`, `micorsoft.com` | high |
| Official domain placed in front of another | `paypal.com.account-verify.example` | high |
| Brand plus other words | `paypal-secure-login.com`, `sbi-kyc-update.in` | medium |
| Brand name on a domain not in the official list | `paypal.example` | medium |
| Brand in a subdomain of another site | `paypal.blogspot.com` | medium |
| Brand starting or ending the name | `netflixbilling.net` | low |
| Brand in the path of an unrelated site | `example.com/paypal/login` | low |

Brands that are ordinary words (apple, chase, steam) or very short (sbi, ups)
only match as whole words, so `purchase.com` and `groups.io` stay quiet, and a
brand's own top-level domain (`.microsoft`, `.sbi`) is trusted.

## Results

Cross-validated **by site** (all URLs of a registered domain in the same
fold), because 51% of the dataset's URLs share a site with another URL and a
random split lets a model recognise sites it has seen:

| Model | ROC-AUC | Accuracy | F1 |
|---|---|---|---|
| v1 (13 features, Random Forest) | 0.879 | 79.8% | 0.799 |
| features (41 features, boosted trees) | 0.950 | 87.4% | 0.873 |
| ngrams (character n-grams) | 0.965 | 89.8% | 0.897 |
| **combined** (default) | **0.972** | **91.1%** | **0.910** |

At its threshold (0.7478, at most 2% of legitimate URLs flagged) the combined
model catches 73.0% of phishing at 97.3% precision.

On data from 1 October 2026, with the model trained on the 2020 dataset:

| | OpenPhish feed (300 phishing URLs) | Tranco top 10,000 home pages |
|---|---|---|
| v1 at 0.5 | 60.7% detected | 15.3% flagged |
| combined at its threshold | 59.0% detected | **1.4% flagged** |

Generated lookalikes of distinctive brand domains (omission, transposition,
homoglyphs, combosquats and more) are caught 94-97% of the time per technique.
Only 6 of the top 10,000 sites (0.06%) get a high-severity lookalike finding.
The full method, the threshold sweep, and every false alarm are in
[docs/BENCHMARK.md](docs/BENCHMARK.md).

## Notebooks

The original notebook workflow, rebuilt on the package and executed in CI:

1. [Data sourcing and exploration](notebooks/01_data_sourcing_and_exploration.ipynb): classes, URL shapes, and how many URLs share a site.
2. [Feature engineering](notebooks/02_feature_engineering_and_preprocessing.ipynb): v1's features and their two bugs, version 2's features, lookalike examples.
3. [Model development](notebooks/03_model_development.ipynb): the four models cross-validated by site and at random, threshold choice, saving the model.
4. [Results and visualization](notebooks/04_results_and_visualization.ipynb): confusion matrix, ROC and precision-recall curves, feature importance, the most confident mistakes, and today's data.

## The data

`data/urls.csv`: 11,430 URLs, half phishing, from *Web page phishing detection*
by Hannousse and Yahiouche (Mendeley Data, 2020,
[doi:10.17632/c2gw7fy2j4.3](https://doi.org/10.17632/c2gw7fy2j4.3), CC BY 4.0),
the dataset version 1 used through its Kaggle mirror. Only the URL and label
columns are kept; see [data/README.md](data/README.md).

## What version 2 changed

Version 1 (August 2025) was four notebooks: 13 lexical features, then
Logistic Regression, Random Forest and SVM compared on a random split, with the
Random Forest winning at F1 0.847. A September 2026 pass verified the notebooks
and fixed stale requirements. Version 2 keeps the notebooks and the approach,
and:

- **adds lookalike-domain detection**, which is what SIH1454 asks for and v1 did
  not have;
- **fixes two feature bugs.** `has_ip` could never match (its pattern expected
  a "/" inside the host name), so the 97 URLs whose host is an IP address, all
  phishing, looked like any other. `is_shortened` searched the whole URL for
  "t.co" and so marked 1,401 URLs, `microsoft.com` among them, as shortened;
- **evaluates honestly**: cross-validation grouped by site, ROC-AUC and a
  false-positive target, and tests on today's phishing and popular sites;
- **bundles the data**, so everything runs without a manual Kaggle download;
- becomes an installable package with a command, a web page and API, 33 tests,
  CI on Linux and Windows that also runs the notebooks, and a Docker image.

## Limitations

- **The URL is all it sees.** No page content, certificates, hosting or
  domain age. A phishing page on an ordinary-looking domain, or on a
  compromised legitimate site, looks legitimate to it.
- **The training data is from 2020.** At its threshold it catches 73% of the
  dataset's phishing but 59% of today's feed, which leans on HTTPS and app
  platforms (`*.vercel.app`, `*.github.io`) far more.
- **Link shorteners score as phishing** (`https://bit.ly/abc` scores 0.97),
  because in this dataset they almost always were. The output says a
  shortener hides the destination; it does not follow it.
- **Popular sites are sometimes flagged:** 1.4% of the top 10,000 home pages,
  mostly file-hosting and redirect domains phishing also uses. In real
  traffic phishing is rare, so most alerts on ordinary browsing would still be
  false: treat a verdict as "worth a second look".
- **The official-domain list is incomplete.** Two real Microsoft domains
  (`onmicrosoft.com`, `s-microsoft.com`) get a high-severity typosquat
  finding. Typo checks are off for short or word-like brands (apple, chase,
  sbi), so `appel.com` is left to the model.
- **Not adversarially tested.** Someone who knows the features can write URLs
  that avoid them.

## Project layout

```
phishing_url_detector/
  urlparts.py    URL parsing and registered domains (offline Public Suffix List)
  lookalike.py   brand list, homoglyphs, typosquats, combosquats
  features.py    v1's features (reproduced) and version 2's 41 features
  model.py       the models, cross-validation by site, thresholds, model files
  check.py       verdicts, findings and signals
  server.py      web page and JSON API (templates/index.html)
  cli.py         the phishing-url-detector command
notebooks/       the four-step workflow
data/            urls.csv and its source
scripts/         benchmark.py (docs/BENCHMARK.md)
tests/           33 tests
```

## License

MIT. See [LICENSE](LICENSE). The data in `data/` is CC BY 4.0 (see
[data/README.md](data/README.md)).
