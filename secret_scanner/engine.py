"""Validate and scan UTF-8 files without modifying their contents."""
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import logging
from pathlib import Path
import stat

from .patterns import scan_line

LOG = logging.getLogger("secret_scanner")
MAX_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__"}


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule: str
    match: str


@dataclass(frozen=True)
class ScanError:
    file: str
    message: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0


def _is_link(metadata) -> bool:
    """Recognize symlinks and Windows mount-point junctions on Python 3.10."""
    return stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0) in (
        0xA0000003,  # IO_REPARSE_TAG_MOUNT_POINT
        0xA000000C,  # IO_REPARSE_TAG_SYMLINK
    )


def scan_path(target: Path, excludes: tuple[str, ...] = ()) -> ScanResult:
    """Scan one file or a directory; retain findings if another file fails."""
    result = ScanResult()
    target = Path(target).absolute()
    LOG.info("Scanning %r", str(target))

    def error(path: Path, action: str, exc: OSError | None = None) -> None:
        # Exception strings can include data supplied by a decoder or caller.
        message = action + (f" ({type(exc).__name__})" if exc else "")
        result.errors.append(ScanError(str(path), message))
        LOG.error("%s: %r", message, str(path))

    def skip(path: Path, reason: str) -> None:
        result.files_skipped += 1
        LOG.warning("Skipped %r: %s", str(path), reason)

    def read_file(path: Path, display: str, size: int) -> None:
        if size > MAX_BYTES:
            skip(path, "larger than 2 MiB")
            return
        try:
            with path.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        except OSError as exc:
            error(path, "Cannot read file", exc)
            return
        if len(data) > MAX_BYTES:
            skip(path, "larger than 2 MiB")
            return
        if b"\x00" in data[:4096]:
            skip(path, "binary NUL byte in first 4 KiB")
            return
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            skip(path, "not UTF-8 text")
            return
        result.files_scanned += 1
        LOG.debug("Read %r", display)
        for number, line in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), start=1):
            for candidate in scan_line(line):
                result.findings.append(Finding(display, number, candidate.rule, candidate.match))

    def visit(path: Path, root: bool = False) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            error(path, "Cannot inspect path", exc)
            return
        if _is_link(metadata):
            if root:
                error(path, "Input must not be a symlink or junction")
            else:
                skip(path, "symlink or junction")
            return
        is_directory = stat.S_ISDIR(metadata.st_mode)
        display = path.name if root else path.relative_to(target).as_posix()
        excluded = any(
            fnmatchcase(display, pattern)
            or (is_directory and fnmatchcase(display + "/", pattern))
            for pattern in excludes
        )
        if excluded:
            if is_directory:
                LOG.debug("Pruned excluded directory %r", display)
            else:
                skip(path, "excluded by glob")
            return
        if is_directory:
            if not root and path.name in SKIP_DIRS:
                LOG.debug("Pruned default directory %r", display)
                return
            try:
                children = sorted(path.iterdir(), key=lambda child: child.name)
            except OSError as exc:
                error(path, "Cannot list directory", exc)
                return
            for child in children:
                visit(child)
        elif stat.S_ISREG(metadata.st_mode):
            read_file(path, display, metadata.st_size)
        else:
            skip(path, "not a regular file")

    visit(target, root=True)
    result.findings.sort(key=lambda item: (item.file, item.line, item.rule))
    LOG.info("Finished: %d files scanned, %d skipped, %d findings, %d errors",
             result.files_scanned, result.files_skipped, len(result.findings), len(result.errors))
    return result