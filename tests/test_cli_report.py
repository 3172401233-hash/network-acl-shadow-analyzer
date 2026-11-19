import io
import unittest
from contextlib import redirect_stdout, redirect_stderr

from acl_analyzer.__main__ import main
from acl_analyzer import parse_rule_text, analyze
from acl_analyzer.report import format_report


RULES_TEXT = """
10 in deny 10.0.0.0/16 -> 0.0.0.0/0 tcp 80
20 in allow 10.0.1.0/24 -> 0.0.0.0/0 tcp 80
30 in allow 10.0.0.0/16 -> 0.0.0.0/0 tcp 443
"""


class CliReportTests(unittest.TestCase):
    def test_cli_stdin_outputs_analysis(self):
        import sys
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(RULES_TEXT)
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                exit_code = main(["-"])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, 0)
        text = output.getvalue()
        self.assertIn("Static ACL analysis", text)
        self.assertIn("fully shadowed: 20", text)
        self.assertIn("action conflicts", text)

    def test_cli_missing_file_returns_error_code(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            exit_code = main(["/nonexistent/path/acl-rules.txt"])
        self.assertEqual(exit_code, 2)
        self.assertIn("error:", errors.getvalue())

    def test_report_lists_remaining_space_and_causes(self):
        report = analyze(parse_rule_text(RULES_TEXT))
        text = format_report(report)
        # Rule 20 is fully shadowed by rule 10 and never matches.
        self.assertIn("rule 20", text)
        self.assertIn("remaining traffic: none", text)
        self.assertIn("shadowed by: 10(deny)", text)
        # Rule 30 only differs by port so it stays active.
        self.assertIn("dport=443", text)


if __name__ == "__main__":
    unittest.main()
