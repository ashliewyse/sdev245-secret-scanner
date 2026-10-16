"""Demo generation tests: generated secrets are invented and local only."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from create_demo import create_examples
from secret_scanner.engine import scan_path


class DemoTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_generated_examples_cover_all_seven_rules(self):
        self.assertEqual(create_examples(self.root), 2)
        result = scan_path(self.root)
        self.assertEqual((result.files_scanned, len(result.findings), len(result.errors)), (2, 8, 0))
        self.assertEqual({finding.rule for finding in result.findings},
                         {"github_pat", "google_api_key", "slack_bot_token", "jwt",
                          "private_key", "password_assignment", "credential_assignment"})

    def test_existing_files_are_never_overwritten(self):
        self.root.joinpath("fake-secrets.txt").write_text("keep student file", encoding="utf-8")
        self.assertEqual(create_examples(self.root), 1)
        self.assertEqual(self.root.joinpath("fake-secrets.txt").read_text(encoding="utf-8"), "keep student file")
        self.assertEqual(create_examples(self.root), 0)