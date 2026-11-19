import unittest

from acl_analyzer import Rule, analyze, parse_rule_text
from acl_analyzer.model import RuleInputError


def rule(rule_id, action, src, dst, protocol="tcp", dst_ports="80",
         direction="in", **kwargs):
    return Rule(rule_id=rule_id, direction=direction, action=action,
                src_cidr=src, dst_cidr=dst, protocol=protocol,
                dst_ports=dst_ports, **kwargs)


class DuplicateTests(unittest.TestCase):
    def test_exact_duplicate_is_fully_shadowed_and_flagged(self):
        args = dict(src="10.0.0.0/24", dst="0.0.0.0/0",
                    protocol="tcp", dst_ports="22")
        report = analyze([rule("r1", "allow", **args),
                          rule("r2", "allow", **args)])
        analysis = report.analyses[1]
        self.assertTrue(analysis.fully_shadowed)
        self.assertEqual(analysis.duplicate_of, ["r1"])
        self.assertTrue(analysis.is_redundant)

    def test_duplicate_rule_id_rejected(self):
        with self.assertRaises(RuleInputError):
            analyze([
                rule("same", "allow", "10.0.0.0/24", "0.0.0.0/0"),
                rule("same", "deny", "10.0.1.0/24", "0.0.0.0/0"),
            ])


class OrderSensitivityTests(unittest.TestCase):
    def test_specific_first_general_second_neither_shadowed(self):
        specific = rule("specific", "allow", "10.0.1.0/24", "0.0.0.0/0")
        general = rule("general", "deny", "10.0.0.0/16", "0.0.0.0/0")
        report = analyze([specific, general])
        self.assertFalse(report.analyses[0].fully_shadowed)
        general_analysis = report.analyses[1]
        self.assertTrue(general_analysis.partially_shadowed)
        self.assertEqual(
            [cause.rule_id for cause in general_analysis.shadowed_by],
            ["specific"])
        # General rule still owns the /16 minus the specific /24.
        residual = [
            rng for box in general_analysis.effective_boxes
            for rng in box.src_ips]
        excluded_start = int.from_bytes(
            bytes((10, 0, 1, 0)), byteorder="big")
        for start, end in residual:
            self.assertTrue(end <= excluded_start or
                            start >= excluded_start + 256)
        covered_count = sum(end - start for start, end in residual)
        self.assertEqual(covered_count, 65536 - 256)

    def test_general_first_specific_second_fully_shadowed(self):
        general = rule("general", "deny", "10.0.0.0/16", "0.0.0.0/0")
        specific = rule("specific", "allow", "10.0.1.0/24", "0.0.0.0/0")
        report = analyze([general, specific])
        self.assertTrue(report.analyses[1].fully_shadowed)


class ProtocolPortStateTests(unittest.TestCase):
    def test_protocol_mismatch_means_no_overlap(self):
        report = analyze([
            rule("tcp", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 protocol="tcp"),
            rule("udp", "allow", "10.0.0.0/24", "0.0.0.0/0",
                 protocol="udp"),
        ])
        for analysis in report.analyses:
            self.assertFalse(analysis.fully_shadowed)
            self.assertEqual(analysis.shadowed_by, [])

    def test_any_protocol_is_partially_covered_by_specific_protocol(self):
        report = analyze([
            rule("tcp-only", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 protocol="tcp", dst_ports="any"),
            rule("all-proto", "allow", "10.0.0.0/24", "0.0.0.0/0",
                 protocol="any", dst_ports="any"),
        ])
        analysis = report.analyses[1]
        self.assertTrue(analysis.partially_shadowed)
        residual_protos = {
            value
            for box in analysis.effective_boxes
            for start, end in box.protocols
            for value in range(start, end)}
        self.assertNotIn(6, residual_protos)
        self.assertIn(17, residual_protos)

    def test_non_contiguous_ports_split_residual(self):
        report = analyze([
            rule("r1", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="80,443"),
            rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="80,443,8080"),
        ])
        analysis = report.analyses[1]
        self.assertTrue(analysis.partially_shadowed)
        residual_ports = sorted(
            port_range
            for box in analysis.effective_boxes
            for port_range in box.dst_ports)
        self.assertEqual(residual_ports, [(8080, 8081)])

    def test_all_ports_covers_every_specific_range(self):
        report = analyze([
            rule("r1", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="1-65535"),
            rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="1-65535"),
        ])
        # Identical ranges: r2 loses everything (full shadow), so use a
        # wider r2 below to prove the residual is port 0.
        self.assertTrue(report.analyses[1].fully_shadowed)

    def test_residual_is_single_uncovered_port(self):
        report = analyze([
            rule("r1", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="1-65535"),
            rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="any"),
        ])
        analysis = report.analyses[1]
        self.assertTrue(analysis.partially_shadowed)
        self.assertEqual(
            [rng for box in analysis.effective_boxes
             for rng in box.dst_ports],
            [(0, 1)])

    def test_literal_full_port_range_covers_everything(self):
        report = analyze([
            rule("r1", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="any"),
            rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="0-65535"),
        ])
        self.assertTrue(report.analyses[1].fully_shadowed)

    def test_different_states_do_not_overlap(self):
        report = analyze([
            rule("r1", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 states="new"),
            rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                 states="established"),
        ])
        self.assertEqual(report.analyses[1].shadowed_by, [])

    def test_directions_are_analyzed_independently(self):
        incoming = rule("in-rule", "deny", "10.0.0.0/24", "0.0.0.0/0",
                        direction="in")
        outgoing = rule("out-rule", "deny", "10.0.0.0/24", "0.0.0.0/0",
                        direction="out")
        report = analyze([incoming, outgoing])
        self.assertEqual(len(report.fully_shadowed_rules), 0)


class EdgeCaseTests(unittest.TestCase):
    def test_empty_rule_set(self):
        report = analyze([])
        self.assertEqual(report.analyses, [])
        self.assertEqual(report.fully_shadowed_rules, [])
        self.assertEqual(report.partially_shadowed_rules, [])
        self.assertEqual(report.conflicting_rules, [])

    def test_mixed_ip_versions_in_one_rule_rejected(self):
        with self.assertRaises(RuleInputError):
            Rule("bad", "in", "deny", "10.0.0.0/24", "2001:db8::/32")

    def test_invalid_port_rejected(self):
        with self.assertRaises(RuleInputError):
            Rule("bad", "in", "deny", "10.0.0.0/24", "0.0.0.0/0",
                 dst_ports="70000")


class ParserTests(unittest.TestCase):
    def test_parse_text_and_analyze(self):
        text = """
        # web policy
        10 in deny 10.0.0.0/24 -> 0.0.0.0/0 tcp 80,443 any new
        20 in allow 10.0.0.0/24 -> 0.0.0.0/0 tcp 80 any new
        30 out allow 2001:db8::/32 -> ::/0 any any
        """
        rules = parse_rule_text(text)
        self.assertEqual(len(rules), 3)
        report = analyze(rules)
        self.assertEqual(report.analyses[1].rule.rule_id, "20")
        self.assertTrue(report.analyses[1].fully_shadowed)
        self.assertEqual(rules[2].version, 6)

    def test_parse_malformed_line(self):
        with self.assertRaises(RuleInputError):
            parse_rule_text("10 in deny 10.0.0.0/24 0.0.0.0/0 tcp 80")


if __name__ == "__main__":
    unittest.main()
