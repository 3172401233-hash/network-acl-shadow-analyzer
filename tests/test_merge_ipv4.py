import unittest

from acl_analyzer import Rule, analyze
from acl_analyzer.space import (
    Box,
    interval_to_cidrs,
    merge_adjacent_boxes,
)


def box(src_range, dst_range, protocol=(6, 7), dport=(80, 81),
        sport=(0, 65536), state=(1, 2)):
    return Box(
        src_ips=(src_range,),
        dst_ips=(dst_range,),
        protocols=(protocol,),
        src_ports=(sport,),
        dst_ports=(dport,),
        states=(state,),
    )


class AdjacentMergeTests(unittest.TestCase):
    def test_interval_to_cidrs_aligned_block(self):
        networks = interval_to_cidrs(0x0A000000, 0x0A010000, 4)
        self.assertEqual([str(net) for net in networks], ["10.0.0.0/16"])

    def test_interval_to_cidrs_unaligned_split(self):
        # 10.0.0.254 - 10.0.1.2 (4 addresses) cannot be one CIDR.
        networks = interval_to_cidrs(0x0A0000FE, 0x0A000102, 4)
        self.assertEqual(
            sorted(str(net) for net in networks),
            ["10.0.0.254/31", "10.0.1.0/31"])

    def test_adjacent_src_ranges_merge_when_other_dims_equal(self):
        left = box((0x0A000000, 0x0A000100), (0, 0x100000000))
        right = box((0x0A000100, 0x0A000200), (0, 0x100000000))
        merged = merge_adjacent_boxes([left, right])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].src_ips, ((0x0A000000, 0x0A000200),))

    def test_non_adjacent_ranges_stay_separate(self):
        left = box((0x0A000000, 0x0A000100), (0, 0x100000000))
        right = box((0x0A000200, 0x0A000300), (0, 0x100000000))
        merged = merge_adjacent_boxes([left, right])
        self.assertEqual(len(merged), 2)

    def test_residual_fragments_merge_after_cidr_shadow(self):
        rules = [
            Rule(rule_id="r1", direction="in", action="deny", src_cidr="10.0.0.0/25", dst_cidr="0.0.0.0/0",
                 protocol="tcp", dst_ports="80"),
            Rule(rule_id="r2", direction="in", action="allow", src_cidr="10.0.0.0/24", dst_cidr="0.0.0.0/0",
                 protocol="tcp", dst_ports="80"),
        ]
        analysis = analyze(rules).analyses[1]
        # The residual /25 must remain a single box rather than fragments.
        self.assertEqual(len(analysis.effective_boxes), 1)
        self.assertEqual(analysis.effective_boxes[0].src_ips,
                         ((0x0A000080, 0x0A000100),))


if __name__ == "__main__":
    unittest.main()
