"""Command line entry point: ``python -m acl_analyzer rules.txt``."""

import argparse
import sys

from .analyzer import analyze
from .model import RuleInputError
from .parser import parse_rule_text
from .report import format_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Static IPv4/IPv6 ACL shadow analyzer. "
                    "Does not generate or execute firewall commands.")
    parser.add_argument("rules_file",
                        help="text file containing ordered ACL rules; "
                             "use '-' to read from stdin")
    args = parser.parse_args(argv)

    try:
        if args.rules_file == "-":
            text = sys.stdin.read()
        else:
            with open(args.rules_file, "r", encoding="utf-8") as handle:
                text = handle.read()
        report = analyze(parse_rule_text(text))
    except (OSError, RuleInputError) as exc:
        print("error: {0}".format(exc), file=sys.stderr)
        return 2

    print(format_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
