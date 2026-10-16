"""Text and JSON reports; rendering never changes scan results."""
from dataclasses import asdict
import json
from .engine import ScanResult


def _visible(text: str) -> str:
    """Prevent terminal control sequences in names, errors, or matches."""
    return "".join(character if character.isprintable()
                   else character.encode("unicode_escape").decode("ascii")
                   for character in text)


def _payload(result: ScanResult, redact: bool) -> dict:
    findings = []
    for finding in result.findings:
        item = asdict(finding)
        if redact:
            item["match"] = "[REDACTED]"
        findings.append(item)
    return {
        "findings": findings,
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "findings": len(result.findings),
            "errors": len(result.errors),
        },
        "errors": [asdict(error) for error in result.errors],
    }


def render_json(result: ScanResult, redact: bool = False) -> str:
    """Return one JSON object, with no logging mixed into the report."""
    return json.dumps(_payload(result, redact), indent=2, ensure_ascii=False) + "\n"


def render_text(result: ScanResult, redact: bool = False) -> str:
    """Show every filename, one-based line number, rule, and exact match."""
    rows = [
        f"{_visible(item.file)}:{item.line} [{item.rule}] "
        + ("[REDACTED]" if redact else _visible(item.match))
        for item in result.findings
    ]
    if not rows:
        rows.append("No findings.")
    for error in result.errors:
        rows.append(f"ERROR {_visible(error.file)}: {_visible(error.message)}")
    rows.append(
        f"Summary: {result.files_scanned} files scanned, {result.files_skipped} skipped, "
        f"{len(result.findings)} findings, {len(result.errors)} errors."
    )
    return "\n".join(rows) + "\n"
