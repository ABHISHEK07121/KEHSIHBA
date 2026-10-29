import os
import tempfile
import unittest
from unittest.mock import patch

from app.services.scan_history import list_scans, record_scan, scan_summary


class ScanHistoryTests(unittest.TestCase):
    def test_search_and_verdict_filters_include_high_risk_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"KESHIHBA_HISTORY_DB": f"{directory}\\history.db"},
        ):
            record_scan("website", "https://lookalike.example", "High Risk", 78, ["brand_impersonation"], ["SBI lookalike"], 0, user_id=1)
            record_scan("website", "https://unresolved.example", "Unknown", 0, ["model_conflict"], ["Model conflict"], 0, user_id=1)
            record_scan("email", "message", "Safe", 0, [], [], 0, user_id=1)
            record_scan("website", "https://quiet.example", "No Known Threat Detected", 4, [], [], 0, user_id=1)

            high_risk = list_scans(classification="high risk", user_id=1)
            searched = list_scans(search="lookalike", user_id=1)
            counts = scan_summary(user_id=1)["counts"]

            self.assertEqual(len(high_risk), 1)
            self.assertEqual(high_risk[0]["classification"], "High Risk")
            self.assertEqual(len(searched), 1)
            self.assertEqual(counts["unknown"], 1)
            self.assertEqual(counts["high_risk"], 1)
            self.assertEqual(counts["safe"], 2)


if __name__ == "__main__":
    unittest.main()
