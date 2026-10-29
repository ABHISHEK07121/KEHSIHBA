# Research Notes

## Research Goal

Build a working prototype that detects potentially phishing or malicious websites and phishing emails using transparent rule-based analysis.

## Dataset Methodology

The current experiments use raw source dataset snapshots stored under `dataset/raw/`, not manually cleaned datasets. The email CSV and URL Parquet files are kept unchanged from their pinned sources. Preprocessing is limited to reproducible training-script operations such as reading valid labeled rows, selecting documented fields, vectorizing content, and applying the declared split.

In the paper, state that the datasets were evaluated in raw form. Also report the dataset source, revision, license, row count, label meanings, split method, and limitations. Do not claim that the data was cleaned unless a future cleaning step is explicitly added and documented.

## Evaluation Metrics

Future evaluation can measure:

- Accuracy
- Precision
- Recall
- F1-score
- False-positive rate
- False-negative rate
- Average response time

No experimental results should be reported until real tests are performed.
