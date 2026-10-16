from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class CliTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "café sample.txt"
        self.source.write_text('clean\npassword="DemoPass123!"\n', encoding="utf-8")

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "scanner.py"), *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=15)

    def test_cli_findings_exit_one_and_private_logs(self):
        completed = self.run_cli(self.source, "--format", "json")
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["findings"][0]["line"], 2)
        self.assertEqual(payload["findings"][0]["file"], self.source.name)
        self.assertNotIn("DemoPass123!", completed.stderr)
        self.assertIn("INFO", completed.stderr)

    def test_clean_file_exit_zero(self):
        self.source.write_text("clean", encoding="utf-8")
        completed = self.run_cli(self.source)
        self.assertEqual(completed.returncode, 0)
        self.assertIn("No findings", completed.stdout)

    def test_empty_directory_exit_zero(self):
        empty = self.root / "empty"
        empty.mkdir()
        completed = self.run_cli(empty, "--format", "json")
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stdout)["summary"]["files_scanned"], 0)

    def test_invalid_path_exit_two_with_json_error(self):
        completed = self.run_cli(self.root / "missing", "--format", "json")
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["summary"]["errors"], 1)
        self.assertNotIn("Traceback", completed.stderr)

    def test_invalid_option_uses_argparse(self):
        completed = self.run_cli(self.source, "--format", "xml")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage:", completed.stderr)

    def test_help_exit_zero(self):
        completed = self.run_cli("--help")
        self.assertEqual(completed.returncode, 0)
        for flag in ("--format", "--output", "--exclude", "--redact", "--verbose"):
            self.assertIn(flag, completed.stdout)

    def test_redacted_json(self):
        completed = self.run_cli(self.source, "--format", "json", "--redact")
        self.assertEqual(json.loads(completed.stdout)["findings"][0]["match"], "[REDACTED]")
        self.assertNotIn("DemoPass123!", completed.stdout + completed.stderr)

    def test_verbose_does_not_expose_secrets(self):
        completed = self.run_cli(self.source, "--verbose")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("DEBUG", completed.stderr)
        self.assertNotIn("DemoPass123!", completed.stderr)

    def test_repeated_exclusions(self):
        other = self.root / "other.log"
        other.write_text('password="AnotherFake!"', encoding="utf-8")
        completed = self.run_cli(self.root, "--exclude", "*.log", "--exclude", "*.txt", "--format", "json")
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stdout)["findings"], [])

    def test_new_output_file_is_utf8_and_stdout_empty(self):
        report = self.root / "report.json"
        completed = self.run_cli(self.source, "--format", "json", "--output", report)
        self.assertEqual((completed.returncode, completed.stdout), (1, ""))
        self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["findings"][0]["file"], self.source.name)

    def test_output_equal_input_preserves_bytes(self):
        before = self.source.read_bytes()
        completed = self.run_cli(self.source, "--output", self.source)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(self.source.read_bytes(), before)

    def test_existing_output_is_unchanged(self):
        report = self.root / "report.txt"
        report.write_bytes(b"keep original")
        completed = self.run_cli(self.source, "--output", report)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report.read_bytes(), b"keep original")

    def test_missing_output_parent(self):
        completed = self.run_cli(self.source, "--output", self.root / "missing" / "report.txt")
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("Traceback", completed.stderr)

    def test_output_directory_is_error(self):
        completed = self.run_cli(self.source, "--output", self.root)
        self.assertEqual(completed.returncode, 2)

    def test_partial_scan_errors_exit_two(self):
        from secret_scanner.cli import main
        from secret_scanner.engine import Finding, ScanError, ScanResult
        result = ScanResult([Finding("good", 1, "password_assignment", "password=FakePass!")],
                            [ScanError("bad", "Cannot read file")], 1, 0)
        stdout, stderr = StringIO(), StringIO()
        with patch("secret_scanner.cli.scan_path", return_value=result), redirect_stdout(stdout), redirect_stderr(stderr):
            code = main([str(self.source), "--format", "json"])
        self.assertEqual(code, 2)
        self.assertEqual(len(json.loads(stdout.getvalue())["findings"]), 1)

    def test_report_write_failure(self):
        from secret_scanner.cli import main
        original_open = Path.open
        output = self.root / "report.txt"
        def denied(path, *args, **kwargs):
            if path == output:
                raise PermissionError("test failure")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", denied), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = main([str(self.source), "--output", str(output)])
        self.assertEqual(code, 2)

    def test_stdout_failure_is_controlled(self):
        from secret_scanner.cli import main
        class BrokenOutput(StringIO):
            def write(self, text):
                raise OSError("write failure")
        with redirect_stdout(BrokenOutput()), redirect_stderr(StringIO()):
            code = main([str(self.source)])
        self.assertEqual(code, 2)

    def test_documented_generated_reports_are_ignored_by_git(self):
        import os
        import shutil
        git = os.environ.get("SCANNER_TEST_GIT") or shutil.which("git")
        if not git:
            self.skipTest("Git unavailable for optional packaging check")
        (self.root / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
        subprocess.run([git, "-C", str(self.root), "init", "-q"], check=True, capture_output=True)
        completed = subprocess.run(
            [git, "-C", str(self.root), "check-ignore", "--no-index",
             "report.json", "report.txt", "reports/report.json", "source-fixture.json"],
            capture_output=True, text=True, encoding="utf-8", check=True)
        self.assertEqual(set(completed.stdout.splitlines()),
                         {"report.json", "report.txt", "reports/report.json"})
