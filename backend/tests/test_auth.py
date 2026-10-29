import base64
import os
import smtplib
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.email import EmailAnalysisResponse, URLAnalysisResponse
from app.services.auth import _connect
from app.services.request_limits import _request_times


ORIGIN = "http://localhost:5173"
CSRF_HEADERS = {"Origin": ORIGIN, "X-KESIHBA-CSRF": "1"}
VALID_PDF = base64.b64encode(b"%PDF-1.4 test report").decode("ascii")


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {
                "KESIHBA_AUTH_DB": os.path.join(self.directory.name, "auth.db"),
                "KESHIHBA_HISTORY_DB": os.path.join(self.directory.name, "history.db"),
                "KESIHBA_ALLOWED_ORIGINS": ORIGIN,
                "KESIHBA_SMTP_HOST": "",
                "KESIHBA_SMTP_USERNAME": "",
                "KESIHBA_SMTP_PASSWORD": "",
                "KESIHBA_SMTP_FROM": "",
            },
            clear=False,
        )
        self.environment.start()
        _request_times.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.environment.stop()
        self.directory.cleanup()

    def signup(self) -> dict[str, object]:
        response = self.client.post(
            "/api/auth/signup",
            headers=CSRF_HEADERS,
            json={"name": "Test User", "email": "person@example.com", "password": "Long-Correct-Horse1"},
        )
        self.assertEqual(response.status_code, 200)
        return self.client.post(
            "/api/auth/login",
            headers=CSRF_HEADERS,
            json={"email": "person@example.com", "password": "Long-Correct-Horse1"},
        ).json()

    def test_signup_response_avoids_enumeration_and_login_uses_http_only_cookie(self) -> None:
        response = self.client.post(
            "/api/auth/signup",
            headers=CSRF_HEADERS,
            json={"name": "Test User", "email": "person@example.com", "password": "Long-Correct-Horse1"},
        )
        result = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(result["user"])
        self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(
            self.client.post(
                "/api/auth/signup",
                headers=CSRF_HEADERS,
                json={"name": "Different Name", "email": "person@example.com", "password": "Long-Correct-Horse1"},
            ).json(),
            result,
        )
        login = self.client.post(
            "/api/auth/login",
            headers=CSRF_HEADERS,
            json={"email": "person@example.com", "password": "Long-Correct-Horse1"},
        )
        self.assertIn("HttpOnly", login.headers["set-cookie"])
        self.assertIn("SameSite=lax", login.headers["set-cookie"])
        with closing(_connect()) as connection:
            row = connection.execute("SELECT password_hash FROM users").fetchone()
        self.assertTrue(row["password_hash"].startswith("scrypt$"))
        self.assertNotIn("Long-Correct-Horse1", row["password_hash"])
        self.assertEqual(self.client.get("/api/auth/me").json()["user"]["email"], "person@example.com")

    def test_guest_scans_work_but_history_is_private_and_user_scoped(self) -> None:
        safe_result = URLAnalysisResponse(
            url="https://guest.example",
            classification="Safe",
            risk_score=5,
            model_note="Model unavailable",
            reputation_status="Not checked",
            threat_types=[],
            intelligence_sources=[],
            indicators=[],
            reasons=[],
            explanation="Scan completed",
            recommendation="Review the destination",
        )
        with patch("app.routes.analyze.analyze_url", return_value=safe_result):
            scan = self.client.post("/api/analyze/url", json={"url": "https://guest.example"})
        self.assertEqual(scan.status_code, 200)
        self.assertEqual(scan.json()["classification"], "Safe")
        self.assertEqual(self.client.get("/api/scans?limit=20").status_code, 401)

        self.signup()
        self.assertEqual(self.client.get("/api/scans?limit=20").json(), [])
        user_result = safe_result.model_copy(update={"url": "https://my-scan.example"})
        with patch("app.routes.analyze.analyze_url", return_value=user_result):
            self.client.post("/api/analyze/url", json={"url": "https://my-scan.example"})
        history = self.client.get("/api/scans?limit=20")
        self.assertEqual(history.status_code, 200)
        self.assertEqual([scan["target"] for scan in history.json()], ["https://my-scan.example"])

        self.client.post("/api/auth/logout", headers=CSRF_HEADERS)
        self.assertIsNone(self.client.get("/api/auth/me").json()["user"])
        self.assertEqual(self.client.get("/api/scans?limit=20").status_code, 401)

    def test_guest_can_scan_email_without_authentication(self) -> None:
        email_result = EmailAnalysisResponse(
            classification="Suspicious",
            risk_score=42,
            threat_types=["credential_theft"],
            spam_score=0,
            scam_score=0,
            model_note="Model unavailable",
            intelligence_sources=[],
            indicators=["Urgent account language"],
            reasons=["Urgent account language"],
            extracted_urls=[],
            risk_breakdown={},
            headers={},
            explanation="Local scan completed",
            recommendation="Verify the sender.",
        )
        with patch("app.routes.analyze.analyze_email", return_value=email_result):
            email_response = self.client.post(
                "/api/analyze/email",
                json={"sender": "notice@example.com", "subject": "Review this", "body": "Please review this message."},
            )
        self.assertEqual(email_response.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").json()["user"], None)

    def test_email_send_requires_auth_valid_address_configuration_and_successful_send(self) -> None:
        payload = {"recipient": "recipient@example.com", "report_type": "url", "pdf_base64": VALID_PDF}
        unauthenticated = self.client.post("/api/auth/send-report", headers=CSRF_HEADERS, json=payload)
        self.assertEqual(unauthenticated.status_code, 401)

        self.signup()
        invalid_recipient = self.client.post(
            "/api/auth/send-report",
            headers=CSRF_HEADERS,
            json={**payload, "recipient": "not-an-email"},
        )
        self.assertEqual(invalid_recipient.status_code, 422)
        unconfigured = self.client.post("/api/auth/send-report", headers=CSRF_HEADERS, json=payload)
        self.assertEqual(unconfigured.status_code, 503)
        self.assertIn("not configured", unconfigured.json()["detail"])

        with patch.dict(
            os.environ,
            {
                "KESIHBA_SMTP_HOST": "smtp.example.com",
                "KESIHBA_SMTP_PORT": "587",
                "KESIHBA_SMTP_USERNAME": "mailer",
                "KESIHBA_SMTP_PASSWORD": "server-secret",
                "KESIHBA_SMTP_FROM": "reports@example.com",
            },
        ), patch("app.routes.auth.smtplib.SMTP") as smtp:
            sent = self.client.post("/api/auth/send-report", headers=CSRF_HEADERS, json=payload)
        self.assertEqual(sent.status_code, 200)
        self.assertIn("recipient@example.com", sent.json()["message"])
        smtp.return_value.__enter__.return_value.send_message.assert_called_once()

    def test_signup_and_login_require_csrf_and_login_errors_are_generic(self) -> None:
        rejected = self.client.post(
            "/api/auth/signup",
            json={"name": "Test User", "email": "person@example.com", "password": "Long-Correct-Horse1"},
        )
        self.assertEqual(rejected.status_code, 403)

        self.signup()
        self.client.post("/api/auth/logout", headers=CSRF_HEADERS)
        failed_login = self.client.post(
            "/api/auth/login",
            headers=CSRF_HEADERS,
            json={"email": "person@example.com", "password": "incorrect"},
        )
        self.assertEqual(failed_login.status_code, 401)
        self.assertEqual(failed_login.json()["detail"], "Email or password is incorrect.")

    def test_mail_provider_failures_are_reported_without_exposing_server_errors(self) -> None:
        self.signup()
        with patch.dict(
            os.environ,
            {
                "KESIHBA_SMTP_HOST": "smtp.example.com",
                "KESIHBA_SMTP_USERNAME": "mailer",
                "KESIHBA_SMTP_PASSWORD": "server-secret",
                "KESIHBA_SMTP_FROM": "reports@example.com",
            },
        ), patch("app.routes.auth.smtplib.SMTP", side_effect=smtplib.SMTPException("private provider detail")):
            response = self.client.post(
                "/api/auth/send-report",
                headers=CSRF_HEADERS,
                json={"recipient": "recipient@example.com", "report_type": "email", "pdf_base64": VALID_PDF},
            )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "The report could not be sent. Please try again later.")
        self.assertNotIn("private provider detail", response.text)


if __name__ == "__main__":
    unittest.main()
