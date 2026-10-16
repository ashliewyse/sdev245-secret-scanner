"""Filesystem tests use temporary files and simulated OS failures."""
from io import BytesIO
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from secret_scanner.engine import scan_path

LIMIT = 2 * 1024 * 1024

class EngineTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, data):
        source = self.root / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return source

    def test_bom_crlf_and_unicode_path(self):
        source = self.write("café file.txt", b'\xef\xbb\xbfclean\r\npassword="DemoPass123!"\r\n')
        result = scan_path(self.root)
        self.assertEqual([(f.file, f.line, f.match) for f in result.findings],
                         [(source.name, 2, 'password="DemoPass123!"')])
        self.assertEqual(result.files_scanned, 1)

    def test_single_file_uses_basename(self):
        source = self.write("file.txt", 'password="DemoPass!"')
        self.assertEqual(scan_path(source).findings[0].file, "file.txt")

    def test_empty_directory(self):
        result = scan_path(self.root)
        self.assertEqual((result.files_scanned, result.findings, result.errors), (0, [], []))

    def test_sorted_recursive_paths_and_multiple_matches(self):
        self.write("z.txt", 'password="LastFake!"')
        self.write("nested/a.txt", 'password="FirstFake!" password="SecondFake!"')
        result = scan_path(self.root)
        self.assertEqual([f.file for f in result.findings], ["nested/a.txt", "nested/a.txt", "z.txt"])
        self.assertEqual(result.files_scanned, 2)

    def test_default_directories_and_repeated_excludes(self):
        for name in (".git/x", ".venv/x", "venv/x", "__pycache__/x",
                     "vendor/x", "trace.log", "keep.txt"):
            self.write(name, 'password="FakePass!"')
        result = scan_path(self.root, ("vendor/*", "*.log"))
        self.assertEqual([f.file for f in result.findings], ["keep.txt"])

    def test_size_limit_2_mib(self):
        self.write("boundary.txt", b"A" * LIMIT)
        self.write("oversize.txt", b"A" * (LIMIT + 1))
        result = scan_path(self.root)
        self.assertEqual((result.files_scanned, result.files_skipped), (1, 1))

    def test_nul_first_4_kib(self):
        source = self.write("binary.bin", b'password="DemoPass!"\x00')
        result = scan_path(source)
        self.assertEqual((result.findings, result.files_skipped, result.errors), ([], 1, []))

    def test_invalid_utf8_is_skip(self):
        source = self.write("bad.txt", b'password="DemoPass!"\n\xff')
        result = scan_path(source)
        self.assertEqual((result.findings, result.files_scanned, result.files_skipped), ([], 0, 1))

    def test_missing_input(self):
        result = scan_path(self.root / "missing.txt")
        self.assertEqual(len(result.errors), 1)

    def test_permission_error_retains_other_findings(self):
        bad = self.write("bad.txt", 'password="PrivateFake!"')
        self.write("good.txt", 'password="PublicFake!"')
        original_open = Path.open
        def denied(path, *args, **kwargs):
            if path == bad:
                raise PermissionError("contains source text PrivateFake!")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", denied):
            with self.assertLogs("secret_scanner", level="ERROR") as logged:
                result = scan_path(self.root)
        self.assertEqual([f.file for f in result.findings], ["good.txt"])
        self.assertEqual(len(result.errors), 1)
        self.assertNotIn("PrivateFake!", str(result.errors) + str(logged.output))

    def test_disappearing_file_is_error(self):
        source = self.write("gone.txt", "clean")
        def disappeared(path, *args, **kwargs):
            raise FileNotFoundError("gone")
        with patch.object(Path, "open", disappeared):
            result = scan_path(source)
        self.assertEqual(len(result.errors), 1)

    def test_growing_file_is_bounded_skip(self):
        source = self.write("grows.txt", "small")
        data = BytesIO(b"A" * (LIMIT * 2))
        with patch.object(Path, "open", lambda *args, **kwargs: data):
            result = scan_path(source)
        self.assertEqual((result.files_scanned, result.files_skipped), (0, 1))

    def test_nonregular_node_is_skipped(self):
        source = self.write("pipe", "never read")
        original_lstat = Path.lstat
        def node_stat(path, *args, **kwargs):
            if path == source:
                return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_size=0,
                                       st_file_attributes=0, st_reparse_tag=0)
            return original_lstat(path, *args, **kwargs)
        with patch.object(Path, "lstat", node_stat):
            result = scan_path(self.root)
        self.assertEqual((result.files_scanned, result.files_skipped, result.errors), (0, 1, []))

    def test_windows_junction_metadata_without_new_path_api(self):
        source = self.write("junction", "do not read")
        original_lstat = Path.lstat
        def junction_stat(path, *args, **kwargs):
            if path == source:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_size=0,
                                       st_file_attributes=0x400, st_reparse_tag=0xA0000003)
            return original_lstat(path, *args, **kwargs)
        with patch.object(Path, "lstat", junction_stat):
            direct = scan_path(source)
            nested = scan_path(self.root)
        self.assertEqual(len(direct.errors), 1)
        self.assertEqual((nested.files_scanned, nested.files_skipped), (0, 1))

    def test_real_symlink_is_not_followed(self):
        source = self.write("actual.txt", 'password="FakePass!"')
        link = self.root / "link.txt"
        try:
            link.symlink_to(source)
        except OSError:
            self.skipTest("OS does not permit unprivileged symlink creation")
        result = scan_path(self.root)
        self.assertEqual([f.file for f in result.findings], ["actual.txt"])
        self.assertEqual(result.files_skipped, 1)
        self.assertEqual(len(scan_path(link).errors), 1)

    def test_directory_read_error(self):
        self.write("a.txt", 'password="FakePass!"')
        blocked = self.root / "blocked"
        blocked.mkdir()
        original_iterdir = Path.iterdir
        def denied(path):
            if path == blocked:
                raise PermissionError("blocked")
            return original_iterdir(path)
        with patch.object(Path, "iterdir", denied):
            result = scan_path(self.root)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.errors), 1)


    def test_physical_line_numbers_ignore_non_newline_separators(self):
        for separator in ("\f", "\v", "\u2028", "\u0085"):
            with self.subTest(separator=repr(separator)):
                source = self.write("physical.txt", 'ordinary' + separator + 'text\npassword="FakePass!"\n')
                self.assertEqual(scan_path(source).findings[0].line, 2)
if __name__ == "__main__":
    unittest.main()
