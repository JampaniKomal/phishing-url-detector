# Benchmark

Everything on this page comes from one run of `scripts/benchmark.py` on
1 October 2026. The raw figures are in
[benchmark/results.json](benchmark/results.json). To reproduce them (about 15
minutes; the script downloads the current OpenPhish feed and Tranco list):

```bash
pip install -e ".[dev]"
python scripts/benchmark.py > docs/benchmark/results.json
```

Cross-validation results are deterministic. The out-of-time results change
with the day's feeds.

## 1. The data, and why the split matters

`data/urls.csv` has 11,430 URLs, half of them phishing, from Hannousse and
Yahiouche's *Web page phishing detection* dataset (2020). After dropping one
duplicate, 11,429 URLs remain, from 6,634 registered domains ("sites").

**51% of the URLs share a site with at least one other URL.** One site
contributes 351 URLs. A random train/test split puts URLs of the same site on
both sides, so a model can score well by recognising sites it has already
seen, which is not a skill that carries over to new phishing domains.

Every figure below therefore comes from 5-fold cross-validation **grouped by
site** (scikit-learn's `GroupKFold`): all URLs of a site are in the same fold.
The random split is shown only for comparison.

## 2. Models

| Model | What it is |
|---|---|
| `v1` | Version 1's 13 features and Random Forest, reproduced exactly, bugs included |
| `features` | Version 2's 41 URL features, gradient-boosted trees |
| `ngrams` | Character 3- to 5-grams (TF-IDF), logistic regression |
| `combined` | The average of `features` and `ngrams` (the default) |

| Model | Split | ROC-AUC | Accuracy | Precision | Recall | F1 | False positives |
|---|---|---|---|---|---|---|---|
| v1 | by site | 0.879 | 79.8% | 79.6% | 80.2% | 0.799 | 20.5% |
| features | by site | 0.950 | 87.4% | 87.9% | 86.6% | 0.873 | 11.9% |
| ngrams | by site | 0.965 | 89.8% | 90.6% | 88.8% | 0.897 | 9.3% |
| **combined** | **by site** | **0.972** | **91.1%** | 91.4% | 90.7% | **0.910** | 8.6% |
| v1 | random | 0.916 | 84.1% | 84.0% | 84.3% | 0.842 | 16.0% |
| combined | random | 0.985 | 94.0% | 94.6% | 93.2% | 0.939 | 5.3% |

All at a 0.5 threshold; "false positives" is the share of legitimate URLs
flagged. Version 1 reported F1 0.847 on a random split. Grouped by site, its
model scores 0.799.

### v1's two feature bugs

- `has_ip` used an IPv4 pattern that needs a `/` inside the host name, so it
  never matched. The dataset has 97 URLs whose host is an IP address, and all
  97 are phishing.
- `is_shortened` searched the whole URL for `t.co`, `bit.ly` and similar
  strings, so `microsoft.com` and `blogspot.com` counted as link shorteners. It
  fired on 1,401 URLs.

`features.v1_features` keeps both bugs so that the `v1` row measures what v1
actually did. Version 2's features fix them (`is_ip_host`, `is_shortener`).

## 3. Choosing the threshold

At 0.5, the combined model flags 8.6% of legitimate URLs. That is too many
for a tool people are meant to trust. The saved model's threshold is the
lowest score at which at most 2% of legitimate URLs in cross-validation are
flagged (rounded up, so the 2% holds): **0.7478**.

| At | Recall | Precision | False positives |
|---|---|---|---|
| 0.5 | 90.7% | 91.4% | 8.6% |
| 0.7478 | 73.0% | 97.3% | 2.0% |

`--threshold` overrides it. The sweep in section 4 shows the trade-off on
today's data.

## 4. Today's data (out of time)

The model is trained on all of the 2020 data and tested on data it could not
have seen:

- **phishing:** the 300 URLs in the public
  [OpenPhish feed](https://github.com/openphish/public_feed) on 1 October 2026;
- **legitimate:** the home pages of the 10,000 most popular registered domains
  in the [Tranco list](https://tranco-list.eu/) (list `Q2K34`).

| Model | Threshold | OpenPhish detected | Tranco home pages flagged |
|---|---|---|---|
| v1 | 0.5 | 60.7% | 15.3% |
| combined | 0.5 | 87.7% | 20.3% |
| combined | **0.7478** | **59.0%** | **1.4%** |

Threshold sweep for the combined model:

| Threshold | Dataset recall | Dataset false positives | OpenPhish detected | Tranco flagged |
|---|---|---|---|---|
| 0.50 | 90.7% | 8.6% | 87.7% | 20.3% |
| 0.60 | 85.1% | 4.8% | 80.7% | 8.7% |
| 0.70 | 77.9% | 2.9% | 69.7% | 2.6% |
| **0.7478** | **73.0%** | **2.0%** | **59.0%** | **1.4%** |
| 0.80 | 67.5% | 1.1% | 48.7% | 0.8% |
| 0.90 | 49.1% | 0.2% | 22.0% | 0.1% |

What this shows:

- **Drift is real.** At the saved threshold, the model catches 73% of the 2020
  test phishing but 59% of today's. Phishing in 2026 sits on HTTPS, on app
  platforms (`*.vercel.app`, `*.github.io`, `*.typedream.app`) and on
  ordinary-looking domains far more than in 2020.
- **Short home-page URLs are hard.** The most popular domains' home pages
  (`https://example.com/`) carry almost no URL signal. The top scores among them
  are file-hosting and redirect domains such as `dropboxusercontent.com` (0.97),
  `sharepointonline.com` (0.95) and `tinyurl.com` (0.91), all of which
  phishing does use.
- **Even so, the model generalises.** v1 at 0.5 catches 61% of today's
  phishing while flagging 15% of popular sites. The combined model at its
  threshold catches about the same share (59%) while flagging a tenth as many
  (1.4%).

## 5. Lookalike detection

### Generated lookalikes

For every brand in `lookalike.BRANDS`, the benchmark generates lookalikes of
its official domain with nine techniques (in the style of dnstwist) and counts how
many `lookalike.find` reports.

| Technique | Example | Distinctive brands (6+ letters) | Word-only or 5-letter brands |
|---|---|---|---|
| omission | `paypl.com` | 95.0% | 0% |
| repetition | `paypall.com` | 95.0% | 15.6% |
| transposition | `pyapal.com` | 95.1% | 0% |
| replacement | `paypai.com` | 95.3% | 0% |
| homoglyph | `paypa1.com`, Cyrillic а | 93.9% | 73.7% |
| hyphenation | `pay-pal.com` | 95.2% | 1.5% |
| combosquat | `paypal-login.com` | 94.4% | 71.4% |
| brand as subdomain | `paypal.com.account-verify.com` | 97.2% | 85.7% |
| TLD swap | `paypal.xyz` | 97.2% | 85.7% |

The misses for short or word-like brands (apple, chase, steam, sbi, ups) are
**by design**: one edit away from `apple` or `chase` are thousands of
legitimate domains, so typo-style checks are switched off for them. The
model still scores those URLs.

### False alarms on popular sites

Of the Tranco top 10,000, 2.4% get any lookalike finding and **0.06% (6
domains) get a high-severity one**, which alone makes the verdict phishing:

`googll.store`, `onmicrosoft.com`, `s-microsoft.com`, `oneidrive.org`,
`twister.porn`, `onlinepbx.ru`.

Two of them, `onmicrosoft.com` and `s-microsoft.com`, are real Microsoft
domains missing from the official list. They are reported here rather than
quietly added to the list, because tuning on the test set would make this
number meaningless. Most of the 2.4% are low and medium findings on brands'
own secondary domains (`googleapis.com`, `amazon-adsystem.com`, `google.de`).
That is why a medium finding is shown to the user but does not decide the
verdict.

### In today's phishing

14.3% of the OpenPhish URLs get a lookalike finding, mostly a brand in a
subdomain of an app platform (`secure-coinbase-com-sign-in.typedream.app`,
`microsoft.<unrelated>.com`) or a brand in the path. Only one, `nfacebook.vn`,
is high severity, and the model had already caught it. Today's phishing
mostly does not imitate the domain name; it imitates the page. That is the
main thing a URL-only tool cannot see.

## 6. What this does not measure

- **Page content, hosting, certificates, domain age:** none are used.
- **Precision at a realistic base rate.** Phishing is far rarer than 50% of
  URLs in real traffic, so at a 1.4% false-positive rate most alerts on
  ordinary browsing would still be false. Treat a "phishing" verdict as
  "worth a second look".
- **Adversaries who know the features.** No evaluation here is adaptive.
