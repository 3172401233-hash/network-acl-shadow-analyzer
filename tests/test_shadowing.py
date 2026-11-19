import unittest

from acl_analyzer import Rule, analyze
from acl_analyzer.space import ranges_to_cidrs


def make_rule(rule_id, action, src, dst, protocol="tcp",
              dst_ports="80", direction="in", **kwargs):
    return Rule(rule_id=rule_id, direction=direction, action=action,
                src_cidr=src, dst_cidr=dst, protocol=protocol,
                dst_ports=dst_ports, **kwargs)


class ShadowingTests(unittest.TestCase):
    def test_full_shadow_bigger_prefix_first(self):
        rules = [
            make_rule("r1", "deny", "10.0.0.0/16", "0.0.0.0/0"),
            make_rule("r2", "allow", "10.0.1.0/24", "0.0.0.0/0"),
        ]
        report = analyze(rules)
        first, second = report.analyses

        self.assertFalse(first.fully_shadowed)
        self.assertTrue(second.fully_shadowed)
        self.assertEqual(second.status, "fully_shadowed")
        self.assertEqual([cause.rule_id for cause in second.shadowed_by],
                         ["r1"])
        self.assertEqual(second.effective_boxes, [])
        self.assertIn(rules[1], report.fully_shadowed_rules)

    def test_partial_shadow_keeps_residual_space(self):
        rules = [
            make_rule("r1", "deny", "10.0.0.0/24", "0.0.0.0/0",
                      dst_ports="80"),
            make_rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                      dst_ports="80-100"),
        ]
        report = analyze(rules)
        analysis = report.analyses[1]

        self.assertTrue(analysis.partially_shadowed)
        self.assertEqual([cause.rule_id for cause in analysis.shadowed_by],
                         ["r1"])
        # Only ports 81-100 remain available to the second rule.
        residual_ports = sorted(
            port_range
            for box in analysis.effective_boxes
            for port_range in box.dst_ports)
        self.assertEqual(residual_ports, [(81, 101)])

    def test_partial_shadow_cidr_residual_is_minimal_cidrs(self):
        rules = [
            make_rule("r1", "deny", "10.0.0.0/25", "0.0.0.0/0",
                      dst_ports="any"),
            make_rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                      dst_ports="any"),
        ]
        report = analyze(rules)
        analysis = report.analyses[1]
        self.assertTrue(analysis.partially_shadowed)

        residual_src = ranges_to_cidrs(
            [rng for box in analysis.effective_boxes
             for rng in box.src_ips], 4)
        self.assertEqual([str(net) for net in residual_src],
                         ["10.0.0.128/25"])

    def test_action_conflict_recorded_on_partial_shadow(self):
        rules = [
            make_rule("r1", "deny", "10.0.0.0/24", "0.0.0.0/0"),
            make_rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                      dst_ports="80,443"),
        ]
        report = analyze(rules)
        analysis = report.analyses[1]

        # Port 80 is lost to the earlier deny; 443 still matches r2.
        self.assertTrue(analysis.partially_shadowed)
        self.assertEqual(len(analysis.conflicts), 1)
        self.assertEqual(analysis.conflicts[0].rule_id, "r1")
        self.assertEqual(analysis.conflicts[0].action, "deny")
        self.assertEqual(analysis.redundant_fragments, [])
        residual_ports = sorted(
            port_range
            for box in analysis.effective_boxes
            for port_range in box.dst_ports)
        self.assertEqual(residual_ports, [(443, 444)])

    def test_same_action_overlap_is_redundant_not_conflict(self):
        rules = [
            make_rule("r1", "allow", "10.0.0.0/24", "0.0.0.0/0",
                      dst_ports="any"),
            make_rule("r2", "allow", "10.0.0.0/24", "0.0.0.0/0",
                      dst_ports="22"),
        ]
        report = analyze(rules)
        analysis = report.analyses[1]
        self.assertTrue(analysis.fully_shadowed)
        self.assertTrue(analysis.is_redundant)
        self.assertEqual(analysis.conflicts, [])
        self.assertEqual(
            [cause.rule_id for cause in analysis.redundant_fragments],
            ["r1"])


if __name__ == "__main__":
    unittest.main()
