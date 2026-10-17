# Secret Scanner

A Python CLI for finding possible exposed credentials in a file or directory. Created for the SDEV245 Secret Scanner final project. Seven regex detectors cover passwords, API keys, tokens, and private-key markers.

**Demo video:** [Watch or download the one-minute recording](recordings/Secret-Scanner-One-Minute-Demo-Clean.mp4).

Matches are **candidates**, not proof of a valid or active credential. The scanner works locally and never contacts a provider.

## Run it

Requires **Python 3.10 or later**. There are no third-party dependencies.

Open PowerShell in this project folder:

~~~powershell
python create_demo.py
python scanner.py --help
python scanner.py demo/clean.txt
python scanner.py demo/fake-secrets.txt
python scanner.py demo
python scanner.py demo --format json --redact
~~~

If Python is available through the Windows launcher, replace python with py -3. On the computer used to prepare this project, this bundled interpreter also works:

~~~powershell
$scannerPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $scannerPython create_demo.py
& $scannerPython scanner.py demo
~~~

Run create_demo.py first to create the fake examples locally. The generator preserves existing files. Generated credential-shaped files are ignored by Git, which keeps complete token examples out of the public repository. The demo files deliberately contain invented, nonfunctional values. The single fake-secrets file has **seven findings**, one per rule. The demo directory has **eight findings across three scanned files**, including one nested assignment. The clean file has no findings.

## Arguments and exit codes

~~~text
python scanner.py PATH [--format text|json] [--output PATH]
                      [--exclude GLOB] [--redact] [--verbose]
~~~

| Argument | Behavior |
| --- | --- |
| PATH | One file, or a directory scanned recursively |
| --format | text (default) or json |
| --output | Create a UTF-8 report file; an existing file is never overwritten and its parent must exist |
| --exclude | Repeatable, case-sensitive glob against relative paths with forward slashes |
| --redact | Replace matched strings with [REDACTED] |
| --verbose | DEBUG logs rather than INFO logs |
| -h / --help | Usage and options |

Quote paths containing spaces and glob patterns:

~~~powershell
python scanner.py "C:\My Project" --exclude "*.log" --exclude "vendor/*"
python scanner.py demo --format json --redact --output report.json
~~~

The second command fails safely if report.json already exists. Choose a new filename. The documented report.json/report.txt names and the reports/ folder are ignored by Git; keep other generated reports out of commits too.

| Code | Meaning |
| --- | --- |
| 0 | Scan succeeded with no findings |
| 1 | Scan succeeded with findings |
| 2 | Input, read/traversal, or report-writing error |

**Exit 1 is the expected result when scanning the fake demo.** If one file fails, other findings remain in the report and the exit code is 2. An empty folder succeeds with zero files.

## Results and logging

Ordinary text output includes the exact match required by the assignment:

~~~text
fake-secrets.txt:7 [password_assignment] password="DemoPass123!"
~~~

Each finding contains the filename, one-based line number, rule ID, and matched string. Directory scans use root-relative paths; a single-file scan uses the basename. Findings sort by file, line, rule, then position. Private-key findings show only the opening marker.

JSON output has this structure:

~~~json
{
  "findings": [
    {
      "file": "fake-secrets.txt",
      "line": 7,
      "rule": "password_assignment",
      "match": "[REDACTED]"
    }
  ],
  "summary": {
    "files_scanned": 1,
    "files_skipped": 0,
    "findings": 1,
    "errors": 0
  },
  "errors": []
}
~~~

This is a shortened schema example. An error object contains file and message. Logs go to **stderr** and reports go to **stdout**, or to the output file. INFO logs show the target and final counts, WARNING logs describe skips, ERROR logs describe failures, and DEBUG logs describe traversal. Logs do not include matched values. Terminal control characters are escaped in text reports.

## Detection logic

The first five rules adapt the assigned [regextokens catalog](https://github.com/odomojuli/regextokens). The two assignment rules are project-specific. The exact expressions and comments are in **secret_scanner/patterns.py**.

1. **github_pat**: a classic GitHub PAT prefix followed by exactly 36 alphanumeric characters.

~~~regex
(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])
~~~

2. **google_api_key**: AIza followed by exactly 35 base64url characters. Lookarounds also allow a dash as the last character.

~~~regex
(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])
~~~

3. **slack_bot_token**: xoxb, two numeric IDs of 10–13 digits, and an alphanumeric suffix of 24–34 characters.

~~~regex
(?<![A-Za-z0-9_-])xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}(?![A-Za-z0-9_-])
~~~

4. **jwt**: three base64url segments. The first two begin with ey; the last segment must have at least ten characters. This detects a shape without decoding claims or checking signatures.

~~~regex
(?<![A-Za-z0-9_.-])ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_.-])
~~~

5. **private_key**: a PEM-style private-key opening marker, including RSA, EC, DSA, OPENSSH, PGP, or ENCRYPTED variants.

~~~regex
-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----
~~~

6. **password_assignment**: case-insensitive password, passwd, or pwd assigned a literal value of at least **four characters**.
7. **credential_assignment**: case-insensitive api_key, apikey, api-key, access_token, auth_token, or token assigned a literal value of at least **sixteen characters**.

Both assignment rules use this structure, with NAMES replaced by the rule's alternatives:

~~~regex
(?<![\w-])(?P<key_quote>['"]?)(?:NAMES)(?P=key_quote)[ \t]*[:=][ \t]*(?:"(?P<double>(?:\\[^\r\n]|[^"\\\r\n])*)"|'(?P<single>(?:\\[^\r\n]|[^'\\\r\n])*)'|(?P<bare>[^\s'",;#]+))
~~~

Paired quotes may contain spaces and escaped characters. Unquoted values stop at whitespace, comma, semicolon, or #. Minimum lengths are checked on captured literal values; escapes are preserved, not evaluated. Generic findings contain the whole assignment. Full shell/Windows environment references ($NAME, ${NAME}, $env:NAME, and %NAME%) and common unquoted os.getenv, os.environ, getenv, and process.env expressions are ignored. Dollar-prefixed literals such as $5-DemoPass! are still detected. This filter is not a programming-language parser. Obvious placeholders such as changeme, your_api_key, and angle-bracket values are also ignored.

If a provider token overlaps a generic assignment, the provider rule wins. Different values on the same line remain separate findings.

## File handling and limitations

- Scans UTF-8 text, including a BOM; supports Windows CRLF line endings.
- Skips files larger than **2 MiB**, files with a NUL byte in the first **4 KiB**, and files that cannot decode as UTF-8.
- Prunes .git, .venv, venv, and __pycache__ directories. Exclusions use case-sensitive fnmatch matching; "*.log" also matches nested log paths, and "vendor/*" prunes that folder.
- Does not follow symlinks or Windows junctions. A link supplied as the root is an input error; encountered links count as skips.
- Skipped file/link entries count in files_skipped. Unseen files inside a pruned directory are not counted.
- Scanned files are never modified. Scans are not atomic snapshots; avoid changing the target while scanning.

Regex scanning can produce **false positives**: invented examples, public JWTs, and nonsecret values can resemble credentials. It can also miss real secrets with other provider prefixes, shorter values, unusual variable names, multiline assignments, encoded/obfuscated content, unsupported encodings, or skipped file types. A private-key header can occur without a complete key. No entropy, checksum, signature, or live-service validation is performed. This educational project does not replace a production secret-scanning service.

Use --redact when sharing a report from files containing actual credentials. The included demo needs no real credentials.

## Tests and project structure

~~~powershell
python -m unittest discover -s tests -v
~~~

The suite checks all seven detectors, boundaries, placeholders, overlap handling, recursion, filenames/line numbers, exclusions, file skips, simulated OS errors and junctions, CLI exit codes, text/JSON, redaction, overwrite protection, and logging. A real symlink test skips when Windows denies unprivileged creation; metadata tests still exercise link rejection.

- **patterns.py** detects candidate strings.
- **engine.py** traverses files and returns findings and errors.
- **reporting.py** creates text and JSON.
- **cli.py** validates arguments and writes reports.
- **scanner.py** launches the CLI.
- **tests/** contains automated tests.
- **create_demo.py** generates the fake examples locally; **demo/** contains the clean file and generated examples.

## Recording and final deliverables

Watch or download the [one-minute screen recording](recordings/Secret-Scanner-One-Minute-Demo-Clean.mp4). It shows real execution of the CLI help, a single-file scan, a recursive directory scan, and a redacted JSON report using invented examples. The cursor stays at the bottom-right edge, clear of the results.

The [recording guide](docs/demo-recording.md) documents the walkthrough and commands. The code, README, and actual recording are all included in this repository.

## Sources

- [Assigned regex catalog and implementation reference](https://github.com/odomojuli/regextokens)
- [GitHub personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [Google API keys](https://cloud.google.com/docs/authentication/api-keys)
- [Slack token types](https://api.slack.com/authentication/token-types)
- [JWT specification: RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [Textual key encodings: RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468)
