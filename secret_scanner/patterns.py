"""Seven regex detectors. Provider shapes adapt github.com/odomojuli/regextokens.

Matches are candidates only: this module never validates credentials online.
"""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Candidate:
    rule: str
    match: str
    span: tuple[int, int]
    credential_span: tuple[int, int]


# Lookarounds avoid accepting the beginning of a longer token as a valid match.
PROVIDER_PATTERNS = {
    "github_pat": re.compile(r"(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])"),
    "google_api_key": re.compile(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
    "slack_bot_token": re.compile(
        r"(?<![A-Za-z0-9_-])xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}(?![A-Za-z0-9_-])"
    ),
    "jwt": re.compile(
        r"(?<![A-Za-z0-9_.-])ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}"
        r"\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_.-])"
    ),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    ),
}


def _assignment_pattern(names: str) -> re.Pattern[str]:
    """Keep quotes paired and capture the literal value without evaluating it."""
    return re.compile(
        r"(?<![\w-])(?P<key_quote>['\"]?)(?:" + names + r")(?P=key_quote)"
        r"[ \t]*[:=][ \t]*"
        r"""(?:"(?P<double>(?:\\[^\r\n]|[^"\\\r\n])*)"|'(?P<single>(?:\\[^\r\n]|[^'\\\r\n])*)'|(?P<bare>[^\s'\",;#]+))""",
        re.IGNORECASE,
    )


ASSIGNMENT_PATTERNS = {
    "password_assignment": (_assignment_pattern(r"password|passwd|pwd"), 4),
    "credential_assignment": (
        _assignment_pattern(r"api_key|apikey|api-key|access_token|auth_token|token"), 16
    ),
}
PLACEHOLDERS = {
    "changeme", "example", "none", "null", "your_api_key", "your_token", "your_password"
}


ENV_REFERENCE = re.compile(
    r"\$(?:(?:env:)?[A-Za-z_][A-Za-z0-9_]*|\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\})"
    r"|%[A-Za-z_][A-Za-z0-9_]*%",
    re.IGNORECASE,
)
ENV_ACCESS = re.compile(
    r"(?:os\.(?:getenv[ \t]*\(|environ(?:\[|\.get[ \t]*\())"
    r"|getenv[ \t]*\(|process\.env(?:\.|\[))"
)
def _is_placeholder(value: str) -> bool:
    clean = value.strip()
    return (
        clean.casefold() in PLACEHOLDERS
        or ENV_REFERENCE.fullmatch(clean) is not None
        or (clean.startswith("<") and clean.endswith(">"))
        or (clean.startswith("{{") and clean.endswith("}}"))
    )


def scan_line(text: str) -> list[Candidate]:
    """Find nonduplicated matches, preferring provider rules over assignments."""
    providers = [
        Candidate(rule, match.group(), match.span(), match.span())
        for rule, pattern in PROVIDER_PATTERNS.items()
        for match in pattern.finditer(text)
    ]
    found = list(providers)
    for rule, (pattern, minimum) in ASSIGNMENT_PATTERNS.items():
        for match in pattern.finditer(text):
            group = next(name for name in ("double", "single", "bare") if match.group(name) is not None)
            value = match.group(group)
            if group == "bare" and ENV_ACCESS.match(text, match.start(group)):
                continue
            if len(value) < minimum or _is_placeholder(value):
                continue
            value_span = match.span(group)
            if any(value_span[0] < other.credential_span[1] and other.credential_span[0] < value_span[1]
                   for other in providers):
                continue
            found.append(Candidate(rule, match.group(), match.span(), value_span))
    return sorted(found, key=lambda item: (item.rule, item.span[0]))
