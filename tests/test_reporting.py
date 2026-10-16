import json
import unittest
from secret_scanner.engine import Finding, ScanError, ScanResult
from secret_scanner.reporting import render_json, render_text

class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.result = ScanResult([Finding("nested/config.txt", 2, "password_assignment",
                                         'password="DemoPass123!"')], [], 1, 0)

    def test_json_schema_and_summary(self):
        payload = json.loads(render_json(self.result))
        self.assertEqual(set(payload), {"findings", "summary", "errors"})
        self.assertEqual(payload["findings"], [{"file": "nested/config.txt", "line": 2,
                         "rule": "password_assignment", "match": 'password="DemoPass123!"'}])
        self.assertEqual(payload["summary"], {"files_scanned": 1, "files_skipped": 0,
                                              "findings": 1, "errors": 0})

    def test_text_includes_location_match_and_counts(self):
        text = render_text(self.result)
        for value in ("nested/config.txt:2", 'password="DemoPass123!"', "1 files scanned", "1 findings"):
            self.assertIn(value, text)

    def test_redaction_does_not_mutate_findings(self):
        for renderer in (render_json, render_text):
            text = renderer(self.result, redact=True)
            self.assertNotIn("DemoPass123!", text)
            self.assertIn("[REDACTED]", text)
        self.assertIn("DemoPass123!", self.result.findings[0].match)

    def test_no_findings_is_explicit(self):
        self.assertIn("No findings", render_text(ScanResult()))
        self.assertEqual(json.loads(render_json(ScanResult()))["findings"], [])

    def test_partial_errors_are_rendered(self):
        self.result.errors.append(ScanError("blocked.txt", "Cannot read file"))
        payload = json.loads(render_json(self.result))
        self.assertEqual(payload["summary"]["errors"], 1)
        self.assertEqual(payload["errors"], [{"file": "blocked.txt", "message": "Cannot read file"}])
        self.assertIn("blocked.txt", render_text(self.result))

    def test_terminal_controls_are_escaped(self):
        result = ScanResult([Finding("evil\x1b[31m.txt", 1, "password_assignment",
                                     "password=Demo\x1b[0m")], [], 1, 0)
        text = render_text(result)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\x1b", text)
        self.assertNotIn("\x1b", render_json(result))
