"""Create invented demo credentials locally; never overwrite existing files."""
import argparse
from pathlib import Path
import sys


def create_examples(destination: Path) -> int:
    """Create two demo files from synthetic fragments; return the created count."""
    destination = Path(destination)
    jwt = ".".join(("eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJkZW1vIn0", "NOT_A_REAL_SIGNATURE_123456"))
    examples = [
        "# FAKE DEMO DATA ONLY. None of these values are real credentials.",
        "ghp_" + "A" * 36,
        "AIza" + "B" * 35,
        "xoxb-" + "1" * 10 + "-" + "2" * 13 + "-" + "C" * 24,
        jwt,
        "-----BEGIN " + "PRIVATE KEY-----",
        'password="DemoPass123!"',
        'api_key="FakeCredential123456789"',
    ]
    files = {
        "fake-secrets.txt": "\n".join(examples) + "\n",
        "nested/sample.env": '# FAKE DEMO DATA ONLY\naccess_token="FakeNestedToken123456789"\n',
    }
    created = 0
    for relative, content in files.items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
        except FileExistsError:
            continue
        created += 1
    return created


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate local, fake-only scanner demo files.")
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent / "demo",
                        help="Destination folder (default: this project's demo folder)")
    args = parser.parse_args()
    try:
        count = create_examples(args.directory)
    except OSError as exc:
        print(f"Cannot create demo files ({type(exc).__name__}).", file=sys.stderr)
        return 2
    print(f"Created {count} fake demo files. Existing files were kept.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())