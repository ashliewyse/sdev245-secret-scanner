"""Command-line arguments, logging, report output, and documented exit codes."""
import argparse
from collections.abc import Sequence
import logging
from pathlib import Path
import sys

from .engine import scan_path
from .reporting import render_json, render_text


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find possible exposed secrets in one UTF-8 file or a folder.",
        epilog="Exit codes: 0 = no findings; 1 = findings; 2 = input, scan, or output error.",
    )
    parser.add_argument("path", type=Path, help="File or directory to scan recursively")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format (default: text)")
    parser.add_argument("--output", type=Path, help="Create a UTF-8 report file; existing files are never overwritten")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="Exclude root-relative paths matching this case-sensitive glob; repeatable")
    parser.add_argument("--redact", action="store_true", help="Hide matched strings in the report")
    parser.add_argument("--verbose", action="store_true", help="Enable diagnostic logging on stderr")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    logger = logging.getLogger("secret_scanner")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logger.propagate = False

    result = scan_path(args.path, tuple(args.exclude))
    renderer = render_json if args.format == "json" else render_text
    report = renderer(result, redact=args.redact)
    try:
        if args.output is not None:
            # Exclusive creation protects source files and existing reports.
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(report)
            logger.info("Report written to %r", str(args.output))
        else:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            sys.stdout.write(report)
            sys.stdout.flush()
    except (OSError, UnicodeError) as exc:
        logger.error("Cannot write report (%s)", type(exc).__name__)
        return 2
    return 2 if result.errors else int(bool(result.findings))
