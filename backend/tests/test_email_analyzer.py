import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from app.schemas.email import EmailAnalysisRequest, URLAnalysisRequest
from app.services.email_analyzer import analyze_email, analyze_url
from app.services.email_file_parser import parse_email_upload
from app.services.domain_intelligence import _dns_report, expand_public_link, lookup_dns
from app.services.threat_intelligence import ThreatIntelligence


class EmailAnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.domain_intel_patch = patch("app.services.email_analyzer.analyze_domain", return_value={})
        self.domain_intel_patch.start()
        self.feed_status_patch = patch(
            "app.services.email_analyzer.threat_intelligence.status",
            return_value={
                "feeds": [{
                    "name": "OpenPhish Community",
                    "enabled": True,
                    "updated_at": "2026-10-13T00:00:00+00:00",
                    "error": None,
                }]
            },
        )
        self.feed_status_patch.start()

    def tearDown(self) -> None:
        self.feed_status_patch.stop()
        self.domain_intel_patch.stop()

    def test_email_upload_parser_extracts_eml_headers_and_body(self) -> None:
        raw = (
            b"From: Alert <security@example.com>\r\n"
            b"Reply-To: payments@elsewhere.test\r\n"
            b"Authentication-Results: mx.example; dmarc=fail; spf=fail\r\n"
            b"Subject: Action required\r\n"
            b"To: user@example.com\r\n"
            b"\r\n"
            b"Hello,\r\n"
            b"Please verify your account at https://example.com/login\r\n"
        )

        payload = parse_email_upload("message.eml", raw)

        self.assertEqual(payload.sender, "Alert <security@example.com>")
        self.assertEqual(payload.subject, "Action required")
        self.assertIn("https://example.com/login", payload.body)
        self.assertEqual(payload.headers["reply_to"], "payments@elsewhere.test")
        self.assertIn("dmarc=fail", payload.headers["authentication_results"])

    def test_email_image_ocr_failure_is_reported_as_an_analysis_limitation(self) -> None:
        raw = (
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=scan\r\n\r\n"
            b"--scan\r\nContent-Type: text/plain\r\n\r\nPlease see the attached image.\r\n"
            b"--scan\r\nContent-Type: image/png\r\n"
            b"Content-Disposition: attachment; filename=page.png\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\nAA==\r\n"
            b"--scan--\r\n"
        )
        with patch("app.services.image_ocr.extract_text_from_image", side_effect=RuntimeError("OCR timed out")):
            payload = parse_email_upload("message.eml", raw)

        self.assertIn("OCR failed", payload.headers["analysis_warnings"])
        with patch("app.services.email_analyzer.email_classifier.predict_phishing_probability", return_value=None):
            result = analyze_email(payload)
        self.assertEqual(result.classification, "Unknown")
        self.assertTrue(any("Analysis limitation" in reason for reason in result.reasons))

    def test_malformed_pdf_upload_is_rejected_instead_of_scanned_as_placeholder_text(self) -> None:
        with self.assertRaisesRegex(ValueError, "could not be parsed safely"):
            parse_email_upload("broken.pdf", b"not a PDF")

    def test_email_reply_to_mismatch_and_brand_display_name_are_flagged(self) -> None:
        payload = EmailAnalysisRequest(
            sender="Interbank Support <alert@lookalike.example>",
            subject="Account notice",
            body="Please review this message.",
            headers={"reply_to": "collect@other.example"},
        )
        result = analyze_email(payload)
        self.assertIn("brand_impersonation", result.threat_types)
        self.assertIn("sender_mismatch", result.threat_types)
        self.assertTrue(any("Reply-To domain" in item for item in result.indicators))

    def test_www_link_without_scheme_is_extracted(self) -> None:
        result = analyze_email(EmailAnalysisRequest(body="Review www.example.org/login"))
        self.assertTrue(result.extracted_urls)
        self.assertEqual(result.embedded_url_results[0].hostname, "www.example.org")

    def test_bare_domain_url_with_path_is_extracted_and_analyzed(self) -> None:
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.40),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled", "message": "not configured"}),
        ):
            result = analyze_email(
                EmailAnalysisRequest(
                    body="Please review example.com/login?continue=account and contact help@example.org."
                )
            )

        self.assertEqual(result.extracted_urls, ["example.com/login?continue=account"])
        self.assertEqual(len(result.embedded_url_results), 1)
        self.assertEqual(result.embedded_url_results[0].hostname, "example.com")

    def test_common_file_names_are_not_extracted_as_urls(self) -> None:
        result = analyze_email(
            EmailAnalysisRequest(body="Please review invoice.pdf and attach report.docx.")
        )

        self.assertEqual(result.extracted_urls, [])

    def test_email_distinguishes_spam_and_scam_signals(self) -> None:
        payload = EmailAnalysisRequest(
            sender="offers@example.com",
            subject="Exclusive offer",
            body="Limited time offer. Buy now with this special discount. Send money for a guaranteed returns investment.",
        )

        result = analyze_email(payload)

        self.assertIn("spam", result.threat_types)
        self.assertIn("financial_scam", result.threat_types)
        self.assertGreater(result.spam_score, 0)
        self.assertGreater(result.scam_score, 0)
        self.assertGreater(result.risk_score, 0)
        self.assertEqual(result.headers["subject"], "Exclusive offer")

    def test_marketing_email_with_unsubscribe_link_is_not_phishing_by_default(self) -> None:
        with patch("app.services.email_analyzer.email_classifier.predict_phishing_probability", return_value=0.73):
            result = analyze_email(
                EmailAnalysisRequest(
                    sender="canva@canva.com",
                    subject="You miss me?",
                    body=(
                        "I miss you too! Come hang out? See our latest design inspiration. "
                        "View our new templates and unsubscribe any time."
                    ),
                )
            )

        self.assertEqual(result.email_category, "marketing_promotional")
        self.assertIn("marketing", result.security_verdict.lower())
        self.assertNotIn("phishing", result.threat_assessment)
        self.assertEqual(result.model_score, 73)

    def test_feed_match_marks_email_link_as_malicious(self) -> None:
        with patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=["OpenPhish Community"]):
            result = analyze_email(EmailAnalysisRequest(body="Review https://suspicious.example/login"))

        self.assertEqual(result.classification, "Malicious")
        self.assertIn("phishing", result.threat_types)
        self.assertEqual(result.intelligence_sources, ["OpenPhish Community"])
        self.assertEqual(result.embedded_url_results[0].classification, "Malicious")

    def test_url_path_does_not_count_as_email_credential_request(self) -> None:
        result = analyze_email(
            EmailAnalysisRequest(body="Visit this page: https://example.com/login")
        )

        self.assertNotIn("credential_theft", result.threat_types)
        self.assertTrue(result.embedded_url_results)
        self.assertEqual(result.embedded_url_results[0].classification, "No Known Threat Detected")

    def test_payment_language_alone_does_not_make_a_url_suspicious(self) -> None:
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.40),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled", "message": "not configured"}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://paypal.com/checkout/payment"))

        self.assertEqual(result.classification, "No Known Threat Detected")
        self.assertNotIn("phishing", result.threat_types)

    def test_url_result_returns_components_and_explicit_check_statuses(self) -> None:
        domain_report = {
            "registered_domain": "example.org",
            "dns": {"status": "checked"},
            "ssl": {"checked": True, "valid": True},
            "rdap": {"checked": True},
            "certificate_transparency": {"checked": True},
        }
        with (
            patch("app.services.email_analyzer.analyze_domain", return_value=domain_report),
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.32),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "clean_or_unknown", "checked_at": "2026-10-21T00:00:00Z"}),
            patch("app.services.email_analyzer.threat_intelligence.lookup_google_safe_browsing", return_value={"status": "no_match", "checked_at": "2026-10-21T00:00:00Z"}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://login.example.org:8443/path?next=%2Faccount"))

        self.assertEqual(result.url_components["scheme"], "https")
        self.assertEqual(result.url_components["hostname"], "login.example.org")
        self.assertEqual(result.url_components["registered_domain"], "example.org")
        self.assertEqual(result.url_components["subdomain"], "login")
        self.assertEqual(result.url_components["port"], 8443)
        self.assertEqual(result.url_components["path"], "/path")
        self.assertEqual(result.checks["threat_intelligence"], "no_match")
        self.assertEqual(result.checks["dns_analysis"], "completed")
        self.assertEqual(result.checks["tls_analysis"], "completed")
        self.assertEqual(result.checks["redirect_analysis"], "not_checked")
        self.assertEqual(result.checks["webpage_analysis"], "not_checked")
        self.assertIsNone(result.confidence)
        self.assertTrue(any("not fetched or rendered" in item for item in result.limitations))

    def test_url_result_does_not_summarize_mixed_provider_failures_as_no_match(self) -> None:
        failed_feed_status = {
            "feeds": [{
                "name": "OpenPhish Community",
                "enabled": True,
                "updated_at": "2026-10-20T00:00:00+00:00",
                "error": "Timeout",
            }]
        }
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.32),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled"}),
            patch("app.services.email_analyzer.threat_intelligence.lookup_google_safe_browsing", return_value={"status": "no_match"}),
            patch("app.services.email_analyzer.threat_intelligence.status", return_value=failed_feed_status),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://example.org/"))

        self.assertEqual(result.checks["openphish"], "error")
        self.assertEqual(result.checks["google_safe_browsing"], "no_match")
        self.assertEqual(result.checks["threat_intelligence"], "unknown")

    def test_external_redirect_target_is_reported_as_a_weak_signal(self) -> None:
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.40),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled", "message": "not configured"}),
        ):
            result = analyze_url(
                URLAnalysisRequest(
                    url="https://example.org/continue?next=https%3A%2F%2Foutside.example%2Flogin"
                )
            )

        self.assertIn("external_redirect", result.threat_types)
        self.assertTrue(any("redirect parameter" in item for item in result.indicators))
        self.assertNotEqual(result.classification, "Malicious")

    def test_supplied_new_payment_page_url_is_at_least_suspicious_when_age_is_confirmed(self) -> None:
        domain_report = {
            "checks": [{
                "severity": "warning",
                "weight": 35,
                "message": "Very new domain (24 days old). Treat unexpected login and payment pages with caution.",
            }]
        }
        with (
            patch("app.services.email_analyzer.analyze_domain", return_value=domain_report),
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.44),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled", "message": "not configured"}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://we.nkzddte.com/"))

        self.assertEqual(result.classification, "Suspicious")
        self.assertGreaterEqual(result.risk_score, 35)
        self.assertIn("new_or_unverified_domain", result.threat_types)

    def test_supplied_url_with_reported_risk_and_unusual_domain_shape_is_not_labeled_safe(self) -> None:
        domain_report = {
            "checks": [{
                "severity": "warning",
                "weight": 20,
                "message": "Domain-age evidence is limited.",
            }]
        }
        with (
            patch("app.services.email_analyzer.analyze_domain", return_value=domain_report),
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.444),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled", "message": "not configured"}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://we.nkzddte.com/"))

        self.assertEqual(result.classification, "Suspicious")
        self.assertEqual(result.model_prediction, "no_high_score_signal")
        self.assertIn("suspicious_domain_structure", result.threat_types)
        self.assertGreaterEqual(result.risk_score, 35)

    def test_missing_url_model_is_unknown_when_other_checks_are_inconclusive(self) -> None:
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=None),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled", "message": "not configured"}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://example.org/"))

        self.assertEqual(result.classification, "Unknown")
        self.assertEqual(result.risk_level, "unknown")

    def test_failed_threat_feed_refresh_is_visible_and_not_reported_as_a_match_or_clean_result(self) -> None:
        feed_status = {
            "feeds": [{
                "name": "OpenPhish Community",
                "enabled": True,
                "updated_at": "2026-10-12T00:00:00+00:00",
                "last_attempt_at": "2026-10-13T00:00:00+00:00",
                "error": "Timeout",
            }]
        }
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.20),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value={"status": "disabled", "message": "not configured"}),
            patch("app.services.email_analyzer.threat_intelligence.status", return_value=feed_status),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://example.org/"))

        self.assertEqual(result.intelligence_sources, [])
        self.assertEqual(result.threat_intelligence["feed_status"], feed_status["feeds"])
        self.assertEqual(result.classification, "Unknown")
        self.assertTrue(any("refresh failed" in warning and "previous snapshot" in warning for warning in result.warnings))

    def test_high_confidence_model_signal_increases_email_risk(self) -> None:
        with patch("app.services.email_analyzer.email_classifier.predict_phishing_probability", return_value=0.91):
            result = analyze_email(EmailAnalysisRequest(body="A neutral-looking message with no links."))

        self.assertEqual(result.model_score, 91)
        self.assertTrue(result.model_used)
        self.assertIn("phishing", result.threat_types)
        self.assertEqual(result.classification, "Suspicious")

    def test_email_embedded_url_uses_url_model_result(self) -> None:
        with patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.92):
            result = analyze_email(EmailAnalysisRequest(body="Please review https://unknown.example/path"))

        self.assertTrue(result.embedded_url_results)
        self.assertEqual(result.embedded_url_results[0].model_score, 92)
        self.assertEqual(result.embedded_url_results[0].classification, "Unknown")
        self.assertEqual(result.embedded_url_results[0].risk_level, "unknown")
        self.assertIn("inconclusive", result.embedded_url_results[0].warnings[0].lower())

    def test_high_model_probability_without_other_evidence_is_not_safe(self) -> None:
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.93),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch(
                "app.services.email_analyzer.threat_intelligence.lookup_virustotal",
                return_value={"status": "disabled", "message": "VirusTotal is not configured."},
            ),
            patch("app.services.email_analyzer.analyze_domain", return_value={}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://neutral-example.org"))

        self.assertEqual(result.model_score, 93)
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.classification, "Unknown")
        self.assertEqual(result.risk_level, "unknown")
        self.assertEqual(result.model_probability, 0.93)
        self.assertTrue(result.warnings)

    def test_official_indian_brand_domain_is_not_flagged_as_impersonation(self) -> None:
        with patch("app.services.email_analyzer.analyze_domain", return_value={}):
            result = analyze_url(URLAnalysisRequest(url="https://www.sbi.co.in/"))

        self.assertNotIn("brand_impersonation", result.threat_types)

    def test_sbi_lookalike_domain_is_flagged_as_impersonation(self) -> None:
        with patch("app.services.email_analyzer.analyze_domain", return_value={}):
            result = analyze_url(URLAnalysisRequest(url="https://sbi-secure-login.example.com/"))

        self.assertIn("brand_impersonation", result.threat_types)
        self.assertTrue(any("SBI" in indicator for indicator in result.indicators))

    def test_malformed_url_is_unknown_not_safe(self) -> None:
        result = analyze_url(URLAnalysisRequest(url="ftp://example.org/file"))

        self.assertEqual(result.classification, "Unknown")
        self.assertEqual(result.risk_level, "unknown")
        self.assertIn("Unsupported URL scheme", result.warnings[0])

    def test_missing_local_url_model_is_reported_as_unavailable(self) -> None:
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=None),
            patch("app.services.email_analyzer.analyze_domain", return_value={}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://example.org/"))

        self.assertIsNone(result.model_score)
        self.assertFalse(result.model_used)
        self.assertIn("unavailable", result.model_note.lower())

    def test_multiple_structure_warnings_are_high_risk_not_confirmed_malicious(self) -> None:
        suspicious_url = f"http://user:pass@192.0.2.1/{'a' * 130}?next=%2Flogin"
        with patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=None):
            result = analyze_url(URLAnalysisRequest(url=suspicious_url))

        self.assertEqual(result.classification, "High Risk")
        self.assertEqual(result.risk_level, "high")

    def test_url_analysis_checks_feed_without_fetching_target(self) -> None:
        with patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=["URLhaus Recent"]):
            result = analyze_url(URLAnalysisRequest(url="http://files.example/download"))

        self.assertEqual(result.classification, "Malicious")
        self.assertIn("malware_distribution", result.threat_types)
        self.assertIn("URLhaus Recent", result.intelligence_sources)

    def test_high_confidence_url_model_signal_marks_url_suspicious(self) -> None:
        with patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=0.92):
            result = analyze_url(URLAnalysisRequest(url="http://unknown.example/login"))

        self.assertEqual(result.model_score, 92)
        self.assertTrue(result.model_used)
        self.assertEqual(result.classification, "Suspicious")
        self.assertIn("phishing", result.threat_types)

    def test_virustotal_detection_marks_url_malicious(self) -> None:
        virustotal = {
            "source": "VirusTotal",
            "status": "detected",
            "found": True,
            "enabled": True,
            "checked_at": "2026-10-13T00:00:00+00:00",
            "cached": False,
            "error": None,
            "message": "VirusTotal reports 3 malicious and 1 suspicious engine detections.",
            "malicious": 3,
            "suspicious": 1,
            "harmless": 70,
            "undetected": 10,
            "timeout": 0,
            "total_engines": 84,
            "categories": ["malicious", "phishing"],
            "analysis_date": "2026-10-13T00:00:00+00:00",
            "last_final_url": "https://example.test/login",
            "gui_url": "https://www.virustotal.com/gui/url/test",
        }
        with patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value=virustotal):
            result = analyze_url(URLAnalysisRequest(url="https://example.test/login"))

        self.assertEqual(result.classification, "Malicious")
        self.assertIn("VirusTotal", result.intelligence_sources)
        self.assertIn("phishing", result.threat_types)
        self.assertEqual(result.virustotal, virustotal)
        self.assertIn("VirusTotal reports 3 malicious and 1 suspicious detections.", result.indicators)

class ThreatIntelligenceTests(unittest.TestCase):
    def test_google_safe_browsing_reports_match_and_skips_sensitive_urls(self) -> None:
        service = ThreatIntelligence()
        response = type("Response", (), {
            "status_code": 200,
            "raise_for_status": lambda self: None,
            "json": lambda self: {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]},
        })()
        with patch.dict("os.environ", {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.post", return_value=response
        ) as request:
            result = service.lookup_google_safe_browsing("https://evil.example/login")
            skipped = service.lookup_google_safe_browsing("https://example.org/reset?access_token=private")
        self.assertEqual(result["status"], "detected")
        self.assertEqual(result["threat_types"], ["SOCIAL_ENGINEERING"])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(skipped["status"], "skipped_sensitive_parameters")

    def test_google_safe_browsing_no_match_is_not_safe_and_cache_is_used(self) -> None:
        service = ThreatIntelligence()
        response = type("Response", (), {
            "status_code": 200,
            "raise_for_status": lambda self: None,
            "json": lambda self: {"matches": []},
        })()
        with patch.dict("os.environ", {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.post", return_value=response
        ) as request:
            first = service.lookup_google_safe_browsing("https://unknown.example/")
            second = service.lookup_google_safe_browsing("https://unknown.example/")
        self.assertEqual(first["status"], "no_match")
        self.assertIn("not establish", first["message"])
        self.assertTrue(second["cached"])
        self.assertEqual(request.call_count, 1)

    def test_feed_refresh_normalizes_urls_and_exposes_timestamp(self) -> None:
        service = ThreatIntelligence()
        response = type("Response", (), {"text": "https://evil.example/path#fragment\n", "raise_for_status": lambda self: None})()

        with patch.dict("os.environ", {"URLHAUS_AUTH_KEY": ""}), patch(
            "app.services.threat_intelligence.requests.get", return_value=response
        ):
            service._refresh_openphish()

        self.assertEqual(service.lookup("https://evil.example/path"), ["OpenPhish Community"])
        status = service.status()["feeds"][0]
        self.assertEqual(status["entries"], 1)
        self.assertIsNotNone(status["updated_at"])

    def test_failed_refresh_is_throttled_without_faking_a_success(self) -> None:
        service = ThreatIntelligence()
        service._set_error("OpenPhish Community", "ConnectionError")

        now = datetime.now(timezone.utc).timestamp()
        self.assertFalse(service._is_due("OpenPhish Community", now, 12 * 60 * 60))
        self.assertTrue(service._is_due("OpenPhish Community", now + 5 * 60, 12 * 60 * 60))
        status = service.status()["feeds"][0]
        self.assertIsNone(status["updated_at"])
        self.assertIsNotNone(status["last_attempt_at"])

    def test_virustotal_lookup_uses_environment_key_and_parses_stats(self) -> None:
        service = ThreatIntelligence()
        response = type(
            "Response",
            (),
            {
                "status_code": 200,
                "raise_for_status": lambda self: None,
                "json": lambda self: {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70},
                            "last_analysis_date": 1791849600,
                            "last_final_url": "https://evil.example/login",
                            "last_analysis_results": {
                                "engine": {"category": "phishing"},
                                "detector": {"category": "malicious", "result": "phishing"},
                            },
                        }
                    }
                },
            },
        )()

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.get", return_value=response
        ) as request:
            result = service.lookup_virustotal("https://evil.example/login")

        self.assertEqual(result["malicious"], 2)
        self.assertEqual(result["status"], "detected")
        self.assertEqual(result["total_engines"], 73)
        self.assertEqual(result["last_final_url"], "https://evil.example/login")
        self.assertIn("gui_url", result)
        self.assertIn("phishing", result["categories"])
        self.assertEqual(result["vendor_results"], [{"engine": "detector", "category": "malicious", "result": "phishing"}])
        self.assertEqual(request.call_args.kwargs["headers"], {"x-apikey": "test-key"})

    def test_virustotal_lookup_distinguishes_unknown_from_safe(self) -> None:
        service = ThreatIntelligence()
        response = type(
            "Response",
            (),
            {
                "status_code": 404,
                "raise_for_status": lambda self: None,
            },
        )()

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.get", return_value=response
        ):
            result = service.lookup_virustotal("https://unknown.example/login")

        self.assertEqual(result["status"], "not_found")
        self.assertFalse(result["found"])
        self.assertIn("unknown", result["message"].lower())

    def test_virustotal_lookup_uses_cache_without_second_request(self) -> None:
        service = ThreatIntelligence()
        response = type(
            "Response",
            (),
            {
                "status_code": 404,
                "raise_for_status": lambda self: None,
            },
        )()

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.get", return_value=response
        ) as request:
            first = service.lookup_virustotal("https://unknown.example/login")
            second = service.lookup_virustotal("https://unknown.example/login")

        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(request.call_count, 1)

    def test_virustotal_rate_limit_returns_structured_status(self) -> None:
        service = ThreatIntelligence()
        response = type(
            "Response",
            (),
            {
                "status_code": 429,
                "raise_for_status": lambda self: None,
            },
        )()

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.get", return_value=response
        ):
            result = service.lookup_virustotal("https://unknown.example/login")

        self.assertEqual(result["status"], "rate_limited")
        self.assertEqual(result["error"], "RuntimeError")

    def test_virustotal_skips_sensitive_url_parameters(self) -> None:
        service = ThreatIntelligence()
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.get"
        ) as request:
            result = service.lookup_virustotal("https://example.org/reset?access_token=private")

        self.assertEqual(result["status"], "skipped_sensitive_parameters")
        request.assert_not_called()

    def test_suspicious_virustotal_counts_are_not_labeled_confirmed_malicious(self) -> None:
        response = {
            "source": "VirusTotal",
            "status": "detected",
            "found": True,
            "enabled": True,
            "checked_at": "2026-10-13T00:00:00+00:00",
            "cached": False,
            "error": None,
            "malicious": 0,
            "suspicious": 2,
            "categories": [],
            "message": "suspicious reports",
        }
        with (
            patch("app.services.email_analyzer.url_classifier.predict_phishing_probability", return_value=None),
            patch("app.services.email_analyzer.threat_intelligence.lookup", return_value=[]),
            patch("app.services.email_analyzer.threat_intelligence.lookup_virustotal", return_value=response),
            patch("app.services.email_analyzer.analyze_domain", return_value={}),
        ):
            result = analyze_url(URLAnalysisRequest(url="https://example.org/"))

        self.assertEqual(result.classification, "High Risk")
        self.assertEqual(result.risk_level, "high")

    def test_malformed_virustotal_payload_does_not_crash(self) -> None:
        service = ThreatIntelligence()
        response = type(
            "Response",
            (),
            {
                "status_code": 200,
                "raise_for_status": lambda self: None,
                "json": lambda self: ["unexpected", "shape"],
            },
        )()

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.get", return_value=response
        ):
            result = service.lookup_virustotal("https://evil.example/login")

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "ValueError")
        self.assertEqual(service.status()["virustotal"]["error"], "ValueError")

    def test_malformed_urlhaus_payload_does_not_crash(self) -> None:
        service = ThreatIntelligence()
        response = type(
            "Response",
            (),
            {
                "status_code": 200,
                "raise_for_status": lambda self: None,
                "json": lambda self: ["bad", "shape"],
            },
        )()

        with patch.dict("os.environ", {"URLHAUS_AUTH_KEY": "test-key"}), patch(
            "app.services.threat_intelligence.requests.get", return_value=response
        ):
            service._refresh_urlhaus()

        status = service.status()["feeds"][1]
        self.assertEqual(status["error"], "ValueError")
        self.assertIsNone(status["updated_at"])


class DomainIntelligenceTests(unittest.TestCase):
    def test_dns_report_returns_requested_record_types(self) -> None:
        def fake_get(_url: str, *, params: dict[str, object], **_kwargs: object) -> object:
            answer = {"type": params["type"], "data": "v=spf1 -all" if params["type"] == 16 else "record"}
            return type(
                "Response",
                (),
                {
                    "raise_for_status": lambda self: None,
                    "json": lambda self: {"Answer": [answer]},
                },
            )()

        with patch("app.services.domain_intelligence.requests.get", side_effect=fake_get):
            result = _dns_report("example.org")

        self.assertEqual(set(result["records"]), {"A", "AAAA", "CNAME", "MX", "NS", "TXT"})
        self.assertTrue(result["mx_found"])
        self.assertTrue(result["spf_found"])
        self.assertEqual(result["status"], "checked")

    def test_private_link_expansion_is_blocked_without_connecting(self) -> None:
        result = expand_public_link("http://127.0.0.1/admin")
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["final_url"])

    def test_dns_tools_do_not_return_records_for_private_destinations(self) -> None:
        with patch(
            "app.services.domain_intelligence._resolve_public_addresses",
            return_value=[],
        ):
            result = lookup_dns("private.example")

        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["records"])


if __name__ == "__main__":
    unittest.main()
