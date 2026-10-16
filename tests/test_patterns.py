"""Detector tests using invented credentials only."""
import unittest
from secret_scanner.patterns import scan_line

GITHUB = "ghp_" + "A" * 36
GOOGLE = "AIza" + "B" * 35
SLACK = "xoxb-" + "1" * 10 + "-" + "2" * 13 + "-" + "C" * 24
JWT = ".".join(("eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJkZW1vIn0", "NOT_A_REAL_SIGNATURE_123456"))

class PatternTests(unittest.TestCase):
    def test_all_seven_detectors(self):
        cases = [(GITHUB, "github_pat"), (GOOGLE, "google_api_key"),
                 (SLACK, "slack_bot_token"), (JWT, "jwt"),
                 ("-----BEGIN " + "PRIVATE KEY-----", "private_key"),
                 ('password="DemoPass123!"', "password_assignment"),
                 ('api_key="FakeCredential123456789"', "credential_assignment")]
        for text, rule in cases:
            with self.subTest(rule=rule):
                self.assertEqual([(c.rule, c.match) for c in scan_line(text)], [(rule, text)])

    def test_github_exact_length_and_boundaries(self):
        self.assertEqual(scan_line(GITHUB)[0].match, GITHUB)
        for text in (GITHUB + "A", GITHUB[:-1], "a" + GITHUB, "_" + GITHUB):
            with self.subTest(text=text):
                self.assertEqual(scan_line(text), [])

    def test_google_lengths_and_boundaries(self):
        for length in (34, 35, 36):
            with self.subTest(length=length):
                self.assertEqual(len(scan_line("AIza" + "B" * length)), int(length == 35))
        self.assertEqual(len(scan_line("AIza" + "B" * 34 + "-")), 1)
        self.assertEqual(scan_line(GOOGLE + "_"), [])

    def test_slack_variable_lengths(self):
        for first in (9, 10, 13, 14):
            for suffix in (23, 24, 34, 35):
                text = "xoxb-" + "1" * first + "-" + "2" * 10 + "-" + "C" * suffix
                with self.subTest(first=first, suffix=suffix):
                    self.assertEqual(len(scan_line(text)), int(10 <= first <= 13 and 24 <= suffix <= 34))
        self.assertEqual(scan_line(SLACK + "-"), [])

    def test_jwt_requires_three_base64url_segments(self):
        self.assertEqual(scan_line(JWT)[0].rule, "jwt")
        for text in ("ey1234567890.ey1234567890.short", JWT + ".extra", JWT.replace(".", "/", 1)):
            with self.subTest(text=text):
                self.assertEqual(scan_line(text), [])

    def test_private_key_variants(self):
        for prefix in ("", "RSA ", "EC ", "DSA ", "OPENSSH ", "PGP ", "ENCRYPTED "):
            text = "-----BEGIN " + prefix + "PRIVATE KEY-----"
            with self.subTest(prefix=prefix):
                self.assertEqual(scan_line(text)[0].match, text)
        self.assertEqual(scan_line("-----BEGIN PUBLIC KEY-----"), [])

    def test_provider_precedence_preserves_other_values(self):
        line = 'api_key="' + GITHUB + '" password="DemoPass123!"'
        self.assertEqual({c.rule for c in scan_line(line)}, {"github_pat", "password_assignment"})

    def test_multiple_distinct_values(self):
        found = scan_line('password="FirstFake!" password="SecondFake!"')
        self.assertEqual([c.match for c in found], ['password="FirstFake!"', 'password="SecondFake!"'])
        self.assertLess(found[0].span[0], found[1].span[0])

    def test_assignment_keyword_variants(self):
        for name in ("password", "PASSWD", "Pwd"):
            with self.subTest(name=name):
                self.assertEqual(scan_line(name + "=FakePass!")[0].rule, "password_assignment")
        for name in ("api_key", "APIKEY", "api-key", "access_token", "auth_token", "token"):
            with self.subTest(name=name):
                self.assertEqual(scan_line(name + " = FakeCredential123456789")[0].rule, "credential_assignment")

    def test_generic_value_thresholds(self):
        for size in (3, 4):
            self.assertEqual(len(scan_line('password="' + "A" * size + '"')), int(size >= 4))
        for size in (15, 16):
            self.assertEqual(len(scan_line('token="' + "A" * size + '"')), int(size >= 16))

    def test_quoted_json_key_and_spaces(self):
        line = '"password": "demo with spaces!"'
        self.assertEqual(scan_line(line)[0].match, line)

    def test_escaped_quote_assignment_is_complete(self):
        line = r'"password": "demo\"quoted value"'
        self.assertEqual(scan_line(line)[0].match, line)

    def test_unquoted_stops_at_comment_or_separator(self):
        for suffix in (" # comment", ", next", "; next", " next"):
            with self.subTest(suffix=suffix):
                self.assertEqual(scan_line("password=DemoPass!" + suffix)[0].match, "password=DemoPass!")

    def test_placeholders_and_references_are_ignored(self):
        for value in ("changeme", "your_api_key", "<placeholder>", "$" + "{VARIABLE}", "{{VARIABLE}}"):
            for name in ("password", "api_key"):
                with self.subTest(name=name, value=value):
                    self.assertEqual(scan_line(name + '="' + value + '"'), [])

    def test_no_match_crosses_line(self):
        self.assertEqual(scan_line('password="short\ncontinued"'), [])
        self.assertEqual(scan_line('password=\nDemoPass!'), [])

    def test_keyword_must_be_a_complete_name(self):
        self.assertEqual(scan_line('notpassword="DemoPass!"'), [])
        self.assertEqual(scan_line('my_api_key="FakeCredential123456789"'), [])

    def test_candidate_spans_match_original_input(self):
        line = 'prefix password="DemoPass!" suffix'
        found = scan_line(line)[0]
        self.assertEqual(line[slice(*found.span)], 'password="DemoPass!"')
        self.assertEqual(line[slice(*found.credential_span)], "DemoPass!")


    def test_dollar_prefixed_literal_is_not_an_environment_reference(self):
        line = '"password": "$5-DemoPass!"'
        self.assertEqual([(c.rule, c.match) for c in scan_line(line)],
                         [("password_assignment", line)])

    def test_supported_environment_reference_forms_are_ignored(self):
        values = ["$DEMO_PASSWORD", "$" + "{DEMO_PASSWORD}", "%DEMO_PASSWORD%",
                  "$env:DEMO_PASSWORD", "os.getenv(\"DEMO_PASSWORD\")",
                  "os.environ[\"DEMO_PASSWORD\"]", "process.env.DEMO_PASSWORD"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(scan_line("password=" + value), [])

    def test_quoted_function_like_literal_is_still_detected(self):
        line = 'password="os.getenv(fake literal)"'
        self.assertEqual(scan_line(line)[0].match, line)
if __name__ == "__main__":
    unittest.main()
