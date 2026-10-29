# Dataset

Use this folder for research datasets and evaluation artifacts.

## Folders

- `raw/`: Original datasets, unchanged.
- `processed/`: Cleaned or transformed datasets for experiments.

Do not store private credentials, cookies, tokens, or personal information in datasets.

## Raw Dataset Policy

This project keeps the downloaded research datasets in `dataset/raw/` and treats them as the primary source files for training and evaluation. These raw files are not manually cleaned, filtered, or edited before use. The training scripts only perform reproducible loading steps such as reading valid rows, selecting the documented label columns, vectorizing text or URLs, and applying the declared train/test split.

For the research paper, describe the datasets as raw source snapshots, not hand-cleaned datasets. If any future cleaning is added, document the exact rule, reason, affected row count, and whether the cleaned version was used for training, validation, or testing.

## Live Threat Intelligence

The backend checks links against public, changing URL intelligence rather than treating an old email corpus as current:

- OpenPhish Community Feed: phishing URLs, updated every 12 hours. The feed is used under the provider's terms: https://openphish.com/terms.html
- URLhaus Recent URLs: recent malware-distribution URLs from the past 3 days. It is enabled only when `URLHAUS_AUTH_KEY` is configured; the provider requires an Auth-Key.

The feed status and last successful refresh times are available at `/api/intelligence/status`. A failed refresh keeps the last successfully loaded snapshot. Neither feed is a labeled email-body dataset: spam and scam message scoring currently uses explainable rules, and the feed results only apply to links. Do not interpret either as a complete or guaranteed verdict.

The existing `original-repo-analysis` CSV is a separate research artifact, not automatically loaded or refreshed by this backend. Its provenance and recency should be verified before using it for model training or claiming evaluation results.

## Email Training Dataset

`raw/phishing_email_multilingual.csv` is the pinned Hugging Face snapshot of [Febriyansyah/phishing-emails-multilingual](https://huggingface.co/datasets/Febriyansyah/phishing-emails-multilingual), revision `81de6750a6658efaa1c0ae5a58acfe2b183d968c`. It was last updated on 8 September 2026 and is MIT-licensed. The downloaded file has 600 rows (300 benign, 300 phishing) and columns `id`, `language`, `text`, and `label` (`0` benign, `1` phishing). SHA-256: `55CE9CF197B28EBAFCB46073DA0213FCCA1626E8A0BFB530CE61B2D2E3407A93`.

The author describes the corpus as synthetic and educational, in English and Indonesian. It is suitable for exercising the training pipeline, not a substitute for recent, independently collected real-world mail. Cite the dataset author and repository when reusing it; MIT license applies to the dataset as published.

Train and evaluate from `backend/`:

```bash
python -m pip install -r requirements.txt
python scripts/audit_datasets.py
python scripts/train_email_cross_corpus.py
```

The audit covers the 600-row synthetic CSV and URL Parquet files; it does not audit the EPVME/Enron corpora. The synthetic baseline trainer uses the CSV and writes `backend/app/models/email_synthetic_baseline.joblib` plus `dataset/processed/email_synthetic_baseline_metrics.json`; it does not overwrite the active cross-corpus model. The active email model and `email_model_metrics.json` are produced by `train_email_cross_corpus.py`. Its score is an uncalibrated model output, and the 85/100 alert threshold is a heuristic, not a validation-selected threshold.

The current exact-duplicate audit found 77 duplicate normalized text groups and 209 duplicate text rows in the synthetic 600-row dataset, with no duplicate-text label conflicts. This baseline must not be described as a real-world evaluation.

## Cross-corpus email benchmark

The larger research benchmark uses two pinned public sources:

- [sunknighteric/EPVME-Dataset](https://github.com/sunknighteric/EPVME-Dataset), revision `f559178dafb015df4e6b35627c495237e6e2c560`: 49,136 EML files described as malicious. Its README says many messages were constructed by combining attack payloads with content from older emails. The repository has a GPL-3.0 license.
- [MWiechmann/enron_spam_data](https://github.com/MWiechmann/enron_spam_data), revision `e73c300263040f84b954e969ac06821c31cff47a`: 16,545 messages labeled non-spam (ham) and 17,171 labeled spam. Only the ham class is used as a benign proxy; ham is not independently verified phishing-free. The repository has a GPL-3.0 license.

The source snapshots are stored locally as `raw/epvme/EPVME_1.zip` through `EPVME_8.zip` and `raw/enron_spam_data.zip`. The trainer discards exact normalized-text duplicates and cross-label conflicts, then samples up to 16,000 records per class with a fixed seed. It evaluates on a stratified, grouped 20% holdout before fitting the final model on the full balanced sample:

```powershell
Set-Location backend
..\.venv\Scripts\python.exe scripts\train_email_cross_corpus.py
```

The generated metric is a cross-corpus research benchmark, not current real-world accuracy. EPVME includes constructed/older malicious messages, and Enron ham is older non-spam mail. The different sources and collection periods can create source artifacts or distribution shift; a near-perfect score may reflect these differences rather than reliable phishing detection. A current, independently labeled, time-separated email evaluation is still required for a real-world effectiveness claim. The raw email snapshots may contain personal information; keep them local and do not publish them.

## Additional public email corpus references

The following open-source or research corpora are references for potential email-detection experiments:

- [Enron Email Dataset](https://www.cs.cmu.edu/~./enron/): archival email corpus. Enron mail is not inherently labeled as phishing; define a defensible labeling and benign-use protocol before using it for phishing detection.
- [Nazario phishing corpus](https://monkey.org/~jose/phishing/): phishing email collection. Verify current availability, provenance, labeling, and reuse terms before including it in an experiment.
- [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/): spam and ham messages useful for spam filtering research. Spam labels should not be treated as equivalent to phishing labels.
- [TREC 2007 Public Spam Corpus](https://plg.uwaterloo.ca/~gvcormac/treccorpus07/): research corpus for spam filtering; verify its message categories and evaluation protocol before adapting it to phishing detection.
- [Wooyun Email XSS Dataset](https://github.com/WhiteRabbitc/Wooyun-Email-XSS-Dataset/tree/master/malious-sample): malicious email XSS samples, potentially relevant to detection of active content in email. Treat this as a specialized malicious-sample source, not a general phishing/benign benchmark.

These are reference sources only; they are not currently part of the project's pinned training snapshots or reported model metrics. Before adding any source, record the exact revision or download date, license/terms, labels, transformations, and hashes, and audit duplicates and split leakage. Do not open active content or visit links contained in corpus messages.

## URL Training Dataset

`raw/fed_phishing_urls_train.parquet` and `raw/fed_phishing_urls_test.parquet` are pinned from [flwrlabs/fed-phishing-urls](https://huggingface.co/datasets/flwrlabs/fed-phishing-urls), revision `941d45362de147c316b05d6b3b00e0aefec33448` (last updated 28 August 2026, Apache-2.0). The dataset card documents `url`, `label`, and `client_id`; labels are `0` benign and `1` phishing/malicious. The official splits contain 1,019,074 train rows and 113,232 test rows. SHA-256: train `b2fbd37d31c3981f2fde21edd06f0d5d9758cd10ee605e68daf5e09b75dc00e3`; test `fa9ee5b47841fea613de37125fc8021779ede1ebfd61aad2fe114d27decb2747`.

The benchmark is derived from public URL datasets and may include stale or inactive links. Never visit URLs from the corpus. A recent repository update does not mean each URL is recent or currently malicious; current checks should continue to use live threat-intelligence feeds.

From `backend/`, install requirements and run `python scripts/audit_datasets.py` before `python scripts/train_url_model.py`. The trainer streams the raw Parquet files in batches, fits only the official train split, evaluates the untouched official test split, and saves the classifier to `backend/app/models/url_text_classifier.joblib` and provenance/metrics to `dataset/processed/url_model_metrics.json`.

Current exact duplicate audit result: 9 duplicate normalized URL rows were found inside the train split, 0 inside the test split, and 5 exact normalized URLs overlap between the official train and test files.

## Reproducibility Notes

Training and audit artifacts record runtime package versions where possible. The current saved metrics indicate that the model artifacts were generated with scikit-learn 1.9.1, while verification on 13 October 2026 used scikit-learn 1.8.0 and emitted model-persistence warnings. For final paper results, use one pinned environment, retrain both models, rerun the dataset audit, and report metrics from that same environment.
