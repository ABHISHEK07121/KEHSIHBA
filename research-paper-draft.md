# KESHIHBA: An Explainable Multi-Input Phishing Triage Prototype for Email, URLs, and Screenshots

**Author(s):** [Add actual author name(s)]  
**Researcher ID / ORCID:** [Add actual ID if applicable]  
**Affiliation:** [Add institution or accurate independent-project description]  
**Corresponding author:** [Add approved contact address]  
**Manuscript status:** Research-paper draft based on repository artifacts reviewed on 13 October 2026

> **Before submission:** Complete the author details, verify every reference and dataset citation in the required citation style, and rerun the experiments in a pinned environment. The metrics below are transcribed from saved project artifacts. They are preliminary dataset-specific classifier results, not evidence of real-world effectiveness or performance of the complete application.

## Abstract

Phishing messages and malicious URLs can expose users to credential theft, financial scams, and malware. This paper presents KESHIHBA, a prototype for triaging suspicious email, URLs, and screenshot-based messages. The system combines explainable content and URL heuristics with local character n-gram classifiers and optional URL threat-intelligence lookups. For screenshot input, optical character recognition (OCR) extracts text that is passed to the email-analysis pipeline; the prototype does not perform image-level phishing classification. In saved offline evaluation artifacts, an email classifier evaluated on a 120-message grouped holdout from a small synthetic bilingual corpus reported 100.00% accuracy, precision, recall, and F1-score. A URL classifier evaluated on 60,000 examples from an official test split reported 90.10% accuracy, 91.86% precision, 89.21% recall, and 90.51% F1-score. These results are limited by dataset composition and evaluation design: the email corpus is small and synthetic, while the URL corpus contains exact train/test overlaps in its complete source files and may include stale URLs. The evaluation does not assess the complete integrated system or establish operational effectiveness. KESHIHBA is therefore presented as an explainable phishing-triage prototype rather than a new classification algorithm or a guarantee of safety.

**Keywords:** phishing detection; email security; malicious URLs; explainable analysis; character n-grams; OCR; threat intelligence; triage

## 1. Introduction

Phishing attempts arrive through different forms of content, including email messages, embedded links, and images of messages. Users must decide whether to trust these inputs while attackers can change message wording, domains, and delivery techniques. A single signal is rarely conclusive: for example, HTTPS indicates an encrypted connection but does not establish that a site is legitimate, and the absence of a reputation-feed match does not prove that a URL is safe.

KESHIHBA is a research prototype designed to bring several forms of evidence into one user-facing triage workflow. It accepts email text or supported document uploads, URLs, and screenshots. It applies deterministic indicators, local email and URL classifiers, and optional URL reputation sources. Results present a classification, heuristic risk score, indicators, and a recommendation. Links extracted from email or screenshot text can be submitted for separate URL analysis.

This paper documents the prototype and reports the saved offline results for its individual classifiers. It focuses on the following research questions:

1. How can email, URL, and OCR-derived screenshot inputs be handled in one triage workflow that exposes evidence to users?
2. What offline performance do the email and URL classifiers report under their documented dataset-specific evaluation procedures?
3. What data and evaluation limitations constrain conclusions about generalization and real-world use?

The contribution is the implemented integration and its documented workflow, not a newly proposed machine-learning algorithm. The current evidence does not show that the prototype prevents attacks, improves user outcomes, or outperforms other products.

## 2. Related work

Learning-based phishing-email classification has been studied by Fette, Sadeh, and Tomasic [1]. Abu-Nimeh et al. compared machine-learning techniques for phishing detection, illustrating the importance of classifier and evaluation choices [2]. URL-oriented research includes machine-learning approaches using URL information [3] and learned URL representations for malicious-URL detection [4]. Tesseract is an established OCR engine and provides background for the screenshot text-extraction component [5].

These studies provide research context, but they are not direct performance baselines for KESHIHBA. Their datasets, collection periods, labels, feature sets, and test protocols have not been shown to match the project’s. A formal submission should expand this section with a documented literature search, verified bibliographic records, and a systematic comparison relevant to the intended research question.

## 3. System design

### 3.1 Architecture

The prototype consists of a React/Vite dashboard, a FastAPI backend, local scikit-learn model artifacts, SQLite scan-history metadata, and an optional Chrome Manifest V3 extension. The extension submits the active HTTP or HTTPS page URL to the backend when the user requests a scan.

The main analysis endpoints are:

- `POST /api/analyze/email`
- `POST /api/analyze/url`
- `POST /api/analyze/urls`
- `POST /api/analyze/screenshot`

The backend also exposes model and threat-intelligence status endpoints. The application supports optional account-scoped scan history and email reports; these product features were not evaluated as part of the classifier metrics in this paper.

### 3.2 Email analysis

The email workflow accepts pasted content or supported file uploads, including `.eml`, `.pdf`, `.doc`, `.docx`, and text/HTML files. It extracts HTTP/HTTPS links from the email body, applies configured content and sender rules, and analyzes extracted links through the URL-analysis service. When the local email model is available, its phishing signal is added only when its estimated phishing probability is at least 85%. This threshold is an implementation setting; it has not been established as an optimal operating point.

The email rules include selected urgency and account-pressure phrases, credential-related terms, payment and financial-scam language, promotional language, and limited sender/brand mismatch checks. Spam and scam signals are produced by hand-authored rules; the project does not train separate spam or scam classifiers.

### 3.3 URL analysis

The URL workflow normalizes and validates the submitted HTTP/HTTPS URL and checks selected structural and lexical properties. These include URL and hostname length, subdomains, IP-address hosts, scheme, encoding, unusual delimiters, recognized shorteners, account/payment terms, and possible brand lookalikes. Depending on availability, the service can also use DNS, TLS certificate, domain-registration-age, and reputation evidence.

The URL analysis endpoint does not browse or render the submitted webpage. Some optional checks make network requests, including DNS lookups, TLS connections to publicly resolved destinations, RDAP queries, and external reputation lookups. OpenPhish Community is used for phishing-feed matching. URLhaus Recent is optional and requires `URLHAUS_AUTH_KEY`; VirusTotal reputation is optional and requires `VIRUSTOTAL_API_KEY`. A failed, unavailable, disabled, or not-found lookup is not treated as proof of safety.

### 3.4 Screenshot analysis

The screenshot service converts an uploaded image to grayscale and attempts text extraction with Tesseract OCR. Extracted text is passed through the email-analysis pipeline, and any extracted links can be inspected separately by the URL analyzer. If OCR fails or finds no readable text, the service reports that limitation and recommends manual review. This is OCR-assisted text analysis, not image-layout analysis or a visual phishing classifier.

### 3.5 Interpretation of outputs

The application may return categories such as `Safe`, `Suspicious`, `High Risk`, `Malicious`, or `Unknown`. These are output categories from the combined application logic; they are not the outcome labels measured in the classifier-only experiments below. The overall risk score is a hand-weighted heuristic capped at 100, not a calibrated probability. The model probability and the overall evidence score are distinct. A `Safe` result means only that configured checks did not cross their thresholds.

## 4. Materials and methods

### 4.1 Email dataset and experiment

The email dataset is `Febriyansyah/phishing-emails-multilingual`, pinned to revision `81de6750a6658efaa1c0ae5a58acfe2b183d968c` and recorded in the project as MIT-licensed [6]. It contains 600 samples: 300 benign and 300 phishing. Labels are 0 for benign and 1 for phishing. Project documentation describes the data as synthetic educational material in English and Indonesian. The saved CSV SHA-256 is:

`55ce9cf197b28ebafcb46073da0213fcca1626e8a0bfb530ce61b2d2e3407a93`

The training procedure uses a scikit-learn pipeline comprising a `TfidfVectorizer` configured for character-within-word n-grams of lengths 3–5, `min_df=2`, `max_features=100000`, and sublinear term frequency, followed by `LogisticRegression` with `class_weight="balanced"`, `max_iter=2000`, and `random_state=42`.

The evaluation split is the first split produced by `StratifiedGroupKFold` with five folds, shuffling, and random seed 42. Groups are formed from case-folded, whitespace-normalized exact message text. The saved run uses 480 training and 120 held-out messages. The evaluation model is fitted on the training partition; after evaluation, a final model is fitted on all 600 messages for use by the application. The 100% result therefore describes the held-out partition, not the final all-data model evaluated on an independent test set.

The dataset audit reports 77 exact normalized duplicate-text groups comprising 209 duplicate rows and no exact duplicate-text label conflicts. Exact grouping helps prevent identical normalized messages from crossing partitions, but it does not detect semantic paraphrases or other source-related similarity.

### 4.2 URL dataset and experiment

The URL dataset is `flwrlabs/fed-phishing-urls`, pinned to revision `941d45362de147c316b05d6b3b00e0aefec33448` and recorded in the project as Apache-2.0-licensed [7]. The official source files contain 1,019,074 training rows and 113,232 test rows. Labels are 0 for benign and 1 for phishing or malicious. The saved train and test SHA-256 values are:

- Train: `b2fbd37d31c3981f2fde21edd06f0d5d9758cd10ee605e68daf5e09b75dc00e3`
- Test: `fa9ee5b47841fea613de37125fc8021779ede1ebfd61aad2fe114d27decb2747`

The URL model uses a character `HashingVectorizer` with n-grams of lengths 3–5, `2^20` features, lowercase conversion, L2 normalization, and `alternate_sign=False`. The classifier is `SGDClassifier(loss="log_loss", alpha=1e-5, random_state=42)` trained incrementally over batches.

The saved run is capped at 300,000 dataset training rows and 60,000 test rows. It adds 12 supplemental benign URLs. Training excludes normalized URLs encountered in the capped training region if those URLs are present in the full official test split. For the recorded run, 4,733 such URLs were excluded. This procedure does not create domain-, campaign-, or time-separated partitions.

The audit of the complete source files reports 14,073 unique exact normalized URLs shared between the official train and test files (14,154 overlapping rows). It also reports exact duplicate URLs within each split. Exact URL checks cannot identify shared domains, campaigns, redirects, or near-duplicate paths. The dataset is derived from public URL sources and may include inactive or stale URLs; do not visit dataset URLs during evaluation.

### 4.3 Metrics

The saved artifacts report accuracy, precision, recall, F1-score, false-positive rate, false-negative rate, and confusion matrices. Confusion matrices use class order `[0, 1]`: benign then phishing for email, and benign then phishing/malicious for URLs.

The evaluation concerns the individual saved classifiers. It does not evaluate the final application’s combined rules, model thresholds, threat feeds, OCR, frontend, or extension. No system-level labeled test set, calibration study, ablation experiment, latency benchmark, or user study is present in the saved results.

## 5. Results

The results in Tables 1 and 2 are transcribed from `dataset/processed/email_model_metrics.json` and `dataset/processed/url_model_metrics.json`. They were not independently reproduced for this manuscript.

**Table 1. Email classifier results on the 120-message held-out partition**

| Metric | Result |
|---|---:|
| Accuracy | 100.00% |
| Precision | 100.00% |
| Recall | 100.00% |
| F1-score | 100.00% |
| False-positive rate | 0.00% |
| False-negative rate | 0.00% |
| Test examples | 120 |

Email confusion matrix (rows: actual; columns: predicted):

|  | Predicted benign | Predicted phishing |
|---|---:|---:|
| Actual benign | 60 | 0 |
| Actual phishing | 0 | 60 |

This result applies only to a small synthetic holdout. It is not evidence of perfect generalization to real email.

**Table 2. URL classifier results on the 60,000-row evaluation subset**

| Metric | Result |
|---|---:|
| Accuracy | 90.10% |
| Precision | 91.86% |
| Recall | 89.21% |
| F1-score | 90.51% |
| False-positive rate | 8.90% |
| False-negative rate | 10.79% |
| Test examples | 60,000 |

URL confusion matrix (rows: actual; columns: predicted):

|  | Predicted benign | Predicted phishing/malicious |
|---|---:|---:|
| Actual benign | 25,714 | 2,512 |
| Actual phishing/malicious | 3,429 | 28,345 |

On this evaluated subset, 2,512 benign examples were classified as positive and 3,429 positive examples were classified as benign. The trade-off between false alarms and missed threats should be assessed for the intended use; the saved results do not establish that the current decision threshold is optimal.

The metric artifacts report scikit-learn 1.9.1. Project notes also record subsequent verification with scikit-learn 1.8.0 and model-persistence warnings. The results should be regenerated in a single pinned environment before final submission.

## 6. Discussion

The implementation demonstrates a workflow that connects multiple input types with several categories of evidence. Email and URL rules provide explicit indicators, character n-gram models provide statistical scores, optional feeds can report known URL reputation, and OCR allows screenshot text to enter the text-analysis path. The application makes uncertainty and service availability visible rather than treating unavailable evidence as a clean result.

The experiments provide preliminary, component-level evidence only. The email classifier’s perfect holdout scores are based on a small synthetic corpus and one 120-message grouped partition. The URL classifier was assessed on a substantially larger subset, but the dataset audit identifies exact duplicate and source-split overlap concerns. Neither result establishes performance on current attacks or on data independent of the collection sources.

The saved metrics cannot show that the integrated system is better than any one component. Establishing that would require a common, labeled, independent evaluation set and ablation experiments that compare rules-only, model-only, reputation-only, and combined configurations. Likewise, the project’s explanation features have not been evaluated for user comprehension or decision quality.

## 7. Limitations and threats to validity

**Dataset validity.** The email data are synthetic, bilingual, and limited to 600 messages. The URL dataset may contain stale examples and known exact overlaps. Near-duplicate, campaign-level, domain-level, and temporal leakage have not been ruled out.

**Measurement validity.** The reported metrics cover offline classifiers, not end-to-end application verdicts. The risk score is heuristic and not calibrated as a probability. The saved artifacts do not include confidence intervals, calibration curves, threshold sweeps, cross-dataset validation, latency measurements, or ablation results.

**Construct validity.** Hand-authored keywords cover only selected patterns and may miss context, obfuscation, or language variation. URL reputation absence is not proof of safety. OCR quality can vary with image quality, layout, and language. The screenshot feature does not assess visual layout or QR codes.

**External validity.** Performance may vary across time, languages, organizations, mail platforms, URL campaigns, and class prevalence. No deployment-scale or user-study evidence establishes that the prototype changes user behavior or reduces successful phishing.

## 8. Ethical and privacy considerations

System outputs should be treated as advisory. Users should not make credential or financial decisions based solely on a verdict. Avoid submitting confidential messages or sensitive URLs unless authorized and necessary. Scan-history targets and other metadata may still be sensitive and should receive appropriate access, retention, and deletion controls.

When optional external reputation services are enabled, URL information may be transmitted to those providers. This behavior should be disclosed and handled according to applicable provider terms. API keys belong in backend-only configuration and must not be committed. Research dataset URLs should not be opened merely to validate them. Dataset licenses and the privacy expectations of message owners should be respected.

## 9. Conclusion

KESHIHBA is an explainable phishing-triage prototype that integrates email, URL, and OCR-derived screenshot text workflows with rule-based evidence, local character n-gram classifiers, and optional URL reputation sources. The saved experiments report 100.00% email accuracy on a 120-message synthetic held-out partition and 90.10% URL accuracy on a 60,000-row subset of an official test file. The dataset and evaluation limitations prevent interpreting these figures as real-world performance guarantees. Further work should prioritize pinned reproducibility, independent recent data, campaign- or time-separated evaluation, end-to-end system metrics, and ablation studies.

## References

1. A. Fette, N. Sadeh, and A. Tomasic, “Learning to Detect Phishing Emails,” in *Proceedings of the 16th International Conference on World Wide Web (WWW ’07)*, 2007, pp. 649–656. DOI: [10.1145/1242572.1242660](https://doi.org/10.1145/1242572.1242660).
2. S. Abu-Nimeh, D. Nappa, X. Wang, and S. Nair, “A Comparison of Machine Learning Techniques for Phishing Detection,” in *Proceedings of the Anti-Phishing Working Groups 2nd Annual eCrime Researchers Summit*, 2007. Verify final publisher bibliographic details before submission.
3. O. K. Sahingoz, E. Buber, O. Demir, and B. Diri, “Machine Learning Based Phishing Detection from URLs,” *Expert Systems with Applications*, vol. 117, pp. 345–357, 2019. DOI: [10.1016/j.eswa.2018.09.029](https://doi.org/10.1016/j.eswa.2018.09.029).
4. H. Le, Q. Pham, D. Sahoo, and S. C. H. Hoi, “URLNet: Learning a URL Representation with Deep Learning for Malicious URL Detection,” 2018. arXiv:1802.03162. DOI: [10.48550/arXiv.1802.03162](https://doi.org/10.48550/arXiv.1802.03162).
5. R. Smith, “An Overview of the Tesseract OCR Engine,” in *Proceedings of the Ninth International Conference on Document Analysis and Recognition (ICDAR 2007)*, vol. 2, 2007, pp. 629–633. DOI: [10.1109/ICDAR.2007.4376991](https://doi.org/10.1109/ICDAR.2007.4376991).
6. Febriyansyah, “phishing-emails-multilingual,” Hugging Face dataset, revision `81de6750a6658efaa1c0ae5a58acfe2b183d968c`. Project-recorded license: MIT. [Dataset page](https://huggingface.co/datasets/Febriyansyah/phishing-emails-multilingual).
7. flwrlabs, “fed-phishing-urls,” Hugging Face dataset, revision `941d45362de147c316b05d6b3b00e0aefec33448`. Project-recorded license: Apache-2.0. [Dataset page](https://huggingface.co/datasets/flwrlabs/fed-phishing-urls).
8. OpenPhish, “OpenPhish Community Feed.” [https://openphish.com/](https://openphish.com/). Terms: [https://openphish.com/terms.html](https://openphish.com/terms.html). Confirm access date and applicable terms at submission.
9. abuse.ch, “URLhaus API.” [https://urlhaus.abuse.ch/api/](https://urlhaus.abuse.ch/api/). Confirm access date and applicable terms at submission.
10. VirusTotal, “URL information API.” [https://docs.virustotal.com/reference/url-info](https://docs.virustotal.com/reference/url-info). Confirm access date and applicable terms at submission.
11. scikit-learn developers, *scikit-learn documentation*. [https://scikit-learn.org/stable/](https://scikit-learn.org/stable/). Cite the exact version used for final training and evaluation.
12. Carnegie Mellon University, â€œThe Enron Email Dataset.â€ [Dataset page](https://www.cs.cmu.edu/~./enron/). Reference source; not included in the reported model metrics.
13. J. Nazario, â€œPhishing Corpus.â€ [Corpus page](https://monkey.org/~jose/phishing/). Reference source; verify provenance and reuse terms before use.
14. Apache SpamAssassin Project, â€œPublic Corpus.â€ [Corpus page](https://spamassassin.apache.org/old/publiccorpus/). Reference source; spam labels are not equivalent to phishing labels.
15. G. V. Cormack, â€œTREC 2007 Public Spam Corpus.â€ [Corpus page](https://plg.uwaterloo.ca/~gvcormac/treccorpus07/). Reference source; not included in the reported model metrics.
16. WhiteRabbitc, â€œWooyun Email XSS Dataset.â€ [Malicious samples](https://github.com/WhiteRabbitc/Wooyun-Email-XSS-Dataset/tree/master/malious-sample). Specialized malicious-sample reference; not a general phishing/benign benchmark.

## Author checklist before submission

- Replace author, affiliation, researcher-ID/ORCID, and contact placeholders with accurate details.
- Verify references and dataset publisher/authorship details in the required style.
- Rerun dataset audits and training in one pinned environment; archive code revision, commands, data hashes, model files, and metrics together.
- Add independent-data and end-to-end system evaluation before making generalization claims.
- Do not claim a novel algorithm, perfect real-world accuracy, calibrated risk probability, or attack-prevention effectiveness based on the current artifacts.
