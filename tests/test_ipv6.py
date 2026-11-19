import unittest

from acl_analyzer import Rule, analyze
from acl_analyzer.space import interval_to_cidrs


class Ipv6Tests(unittest.TestCase):
    def test_ipv6_full_and_partial_shadow(self):
        rules = [
            Rule(rule_id="v6-1", direction="in", action="deny",
                 src_cidr="2001:db8::/32", dst_cidr="2001:db8:aaaa::/48",
                 protocol="tcp", dst_ports="80,443"),
            Rule(rule_id="v6-2", direction="in", action="allow",
                 src_cidr="2001:db8:1::/48", dst_cidr="2001:db8:aaaa::/48",
                 protocol="tcp", dst_ports="443"),
            Rule(rule_id="v6-3", direction="in", action="allow",
                 src_cidr="2001:db8::/32", dst_cidr="2001:db8:aaaa::/48",
                 protocol="tcp", dst_ports="443,80,8080"),
        ]
        report = analyze(rules)
        fully, partially = report.analyses[1], report.analyses[2]

        self.assertTrue(fully.fully_shadowed)
        self.assertEqual(fully.shadowed_by[0].rule_id, "v6-1")
        self.assertTrue(partially.partially_shadowed)

    def test_ipv6_residual_renders_as_v6_cidrs(self):
        rules = [
            Rule(rule_id="v6-1", direction="in", action="deny", src_cidr="2001:db8::/33", dst_cidr="::/0",
                 protocol="tcp", dst_ports="any"),
            Rule(rule_id="v6-2", direction="in", action="allow", src_cidr="2001:db8::/32", dst_cidr="::/0",
                 protocol="tcp", dst_ports="any"),
        ]
        analysis = analyze(rules).analyses[1]
        text = analysis.remaining_fragments_text(
            analyze(rules).protocol_names,
            analyze(rules).state_names)
        self.assertEqual(len(text), 1)
        self.assertIn("src=2001:db8:8000::/33", text[0])
        self.assertIn("dst=::/0", text[0])

    def test_ipv6_interval_to_cidrs(self):
        from ipaddress import IPv6Address
        start = int(IPv6Address("2001:db8::"))
        end = int(IPv6Address("2001:db8::1:0"))  # 65536 addresses -> /112
        networks = interval_to_cidrs(start, end, 6)
        self.assertEqual([str(net) for net in networks],
                         ["2001:db8::/112"])

    def test_mixed_v4_v6_rules_never_overlap_across_families(self):
        rules = [
            Rule(rule_id="v4", direction="in", action="deny", src_cidr="10.0.0.0/8", dst_cidr="0.0.0.0/0",
                 protocol="tcp", dst_ports="any"),
            Rule(rule_id="v6", direction="in", action="allow", src_cidr="2001:db8::/32", dst_cidr="::/0",
                 protocol="tcp", dst_ports="any"),
        ]
        report = analyze(rules)
        for analysis in report.analyses:
            self.assertFalse(analysis.fully_shadowed)
            self.assertEqual(analysis.shadowed_by, [])

    def test_v4_and_v6_identical_text_are_distinct_rules(self):
        rules = [
            Rule(rule_id="a", direction="in", action="deny", src_cidr="0.0.0.0/0", dst_cidr="0.0.0.0/0",
                 protocol="any", dst_ports="any"),
            Rule(rule_id="b", direction="in", action="deny", src_cidr="::/0", dst_cidr="::/0",
                 protocol="any", dst_ports="any"),
        ]
        report = analyze(rules)
        self.assertEqual(len(report.fully_shadowed_rules), 0)


if __name__ == "__main__":
    unittest.main()
