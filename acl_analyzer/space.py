"""Geometric representation of the packet matching space.

A rule is modelled as a point inside a multi-dimensional box:

* source IP interval (integer address space)
* destination IP interval
* IP protocol interval(s)
* source / destination port interval lists
* connection state interval(s)

All sets on a single dimension are stored as sorted, disjoint, half-open
integer intervals ``[start, end)``.  Boxes can be intersected and
subtracted, which lets us compute the residual traffic that every rule
still owns once every preceding rule has claimed its own space.
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from typing import Iterable, List, Optional, Sequence, Tuple

PortRange = Tuple[int, int]

FULL_PORT = (0, 65536)


def merge_ranges(ranges: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping or touching half-open intervals."""
    ordered = sorted((start, end) for start, end in ranges if start < end)
    merged: List[Tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def intersect_ranges(
    left: Sequence[Tuple[int, int]], right: Sequence[Tuple[int, int]]
) -> List[Tuple[int, int]]:
    """Intersect two sorted disjoint interval lists."""
    result: List[Tuple[int, int]] = []
    i = j = 0
    while i < len(left) and j < len(right):
        start = max(left[i][0], right[j][0])
        end = min(left[i][1], right[j][1])
        if start < end:
            result.append((start, end))
        if left[i][1] < right[j][1]:
            i += 1
        else:
            j += 1
    return result


def subtract_ranges(
    base: Sequence[Tuple[int, int]], cut: Sequence[Tuple[int, int]]
) -> List[Tuple[int, int]]:
    """Return ``base - cut`` as a sorted disjoint interval list."""
    result: List[Tuple[int, int]] = []
    for base_start, base_end in base:
        cursor = base_start
        for cut_start, cut_end in cut:
            if cut_end <= cursor:
                continue
            if cut_start >= base_end:
                break
            if cut_start > cursor:
                result.append((cursor, min(cut_start, base_end)))
            cursor = max(cursor, cut_end)
            if cursor >= base_end:
                break
        if cursor < base_end:
            result.append((cursor, base_end))
    return merge_ranges(result)


@dataclass(frozen=True)
class Box:
    """A rectangular region of the packet matching space."""

    src_ips: Tuple[Tuple[int, int], ...]
    dst_ips: Tuple[Tuple[int, int], ...]
    protocols: Tuple[Tuple[int, int], ...]
    src_ports: Tuple[Tuple[int, int], ...]
    dst_ports: Tuple[Tuple[int, int], ...]
    states: Tuple[Tuple[int, int], ...]

    @staticmethod
    def _freeze(value: Sequence[Tuple[int, int]]
                ) -> Tuple[Tuple[int, int], ...]:
        return tuple(tuple(item) for item in value)  # type: ignore[arg-type]

    def with_fields(self, **kwargs: Sequence[Tuple[int, int]]) -> "Box":
        data = {
            "src_ips": self.src_ips,
            "dst_ips": self.dst_ips,
            "protocols": self.protocols,
            "src_ports": self.src_ports,
            "dst_ports": self.dst_ports,
            "states": self.states,
        }
        for name, value in kwargs.items():
            data[name] = self._freeze(value)
        return Box(**data)

    def intersect(self, other: "Box") -> Optional["Box"]:
        parts = {
            "src_ips": intersect_ranges(self.src_ips, other.src_ips),
            "dst_ips": intersect_ranges(self.dst_ips, other.dst_ips),
            "protocols": intersect_ranges(self.protocols, other.protocols),
            "src_ports": intersect_ranges(self.src_ports, other.src_ports),
            "dst_ports": intersect_ranges(self.dst_ports, other.dst_ports),
            "states": intersect_ranges(self.states, other.states),
        }
        if any(not value for value in parts.values()):
            return None
        return Box(**{key: tuple(value) for key, value in parts.items()})

    def subtract(self, other: "Box") -> List["Box"]:
        """Return the non-overlapping boxes that make up ``self - other``."""
        overlap = self.intersect(other)
        if overlap is None:
            return [self]
        return _split_around(self, overlap, (
            "src_ips", "dst_ips", "protocols",
            "src_ports", "dst_ports", "states",
        ))


def _split_around(box: Box, cut: Box, dimensions: Sequence[str]) -> List[Box]:
    """Split ``box`` along the first dimension that ``cut`` does not cover."""
    if not dimensions:
        return []
    dimension = dimensions[0]
    remaining = subtract_ranges(getattr(box, dimension), getattr(cut, dimension))
    pieces = [box.with_fields(**{dimension: remaining})] if remaining else []
    inside = box.with_fields(**{dimension: getattr(cut, dimension)})
    pieces.extend(_split_around(inside, cut, dimensions[1:]))
    return pieces


def subtract_boxes(base: Sequence[Box], cut: Box) -> List[Box]:
    result: List[Box] = []
    for box in base:
        result.extend(box.subtract(cut))
    return result


def interval_to_cidrs(
    start: int, end: int, version: int
) -> List:
    """Convert an aligned-or-not integer IP interval into minimal CIDRs."""
    networks = []
    cursor = start
    width = 32 if version == 4 else 128
    while cursor < end:
        trailing_zeros = (cursor & -cursor).bit_length() - 1 if cursor else width
        max_size_bits = min(trailing_zeros, (end - cursor).bit_length() - 1)
        prefix_len = width - max_size_bits
        if version == 4:
            network = IPv4Network((cursor, prefix_len), strict=False)
        else:
            network = IPv6Network((cursor, prefix_len), strict=False)
        networks.append(network)
        cursor += network.num_addresses
    return networks


def ranges_to_cidrs(ranges: Sequence[Tuple[int, int]], version: int) -> List:
    networks: List = []
    for start, end in ranges:
        networks.extend(interval_to_cidrs(start, end, version))
    return networks


def _merge_boxes_once(boxes: Sequence[Box]) -> Tuple[List[Box], bool]:
    """One merge pass; adjacent IP intervals with identical other dims merge."""
    result: List[Box] = []
    used = [False] * len(boxes)
    merged_any = False
    for index, box in enumerate(boxes):
        if used[index]:
            continue
        current = box
        for other_index in range(index + 1, len(boxes)):
            if used[other_index]:
                continue
            candidate = _try_merge_ip(current, boxes[other_index], "src_ips")
            if candidate is None:
                candidate = _try_merge_ip(current, boxes[other_index], "dst_ips")
            if candidate is not None:
                current = candidate
                used[other_index] = True
                merged_any = True
        used[index] = True
        result.append(current)
    return result, merged_any


def _try_merge_ip(left: Box, right: Box, dimension: str) -> Optional[Box]:
    """Merge two boxes when one IP dimension is adjacent and the rest equal."""
    other_dimensions = [
        name for name in (
            "src_ips", "dst_ips", "protocols",
            "src_ports", "dst_ports", "states",
        ) if name != dimension
    ]
    if any(getattr(left, name) != getattr(right, name)
           for name in other_dimensions):
        return None
    left_ranges = list(getattr(left, dimension))
    right_ranges = list(getattr(right, dimension))
    merged = merge_ranges(left_ranges + right_ranges)
    if len(merged) != len(left_ranges) + len(right_ranges) - 1:
        return None
    return left.with_fields(**{dimension: merged})


def merge_adjacent_boxes(boxes: Sequence[Box]) -> List[Box]:
    """Repeatedly merge boxes with adjacent IP ranges and equal other dims."""
    current = list(boxes)
    while True:
        current, changed = _merge_boxes_once(current)
        if not changed:
            return current


def _format_ports(ranges: Sequence[Tuple[int, int]]) -> str:
    parts = []
    for start, end in ranges:
        if (start, end) == FULL_PORT:
            return "any"
        if end - start == 1:
            parts.append(str(start))
        else:
            parts.append("{0}-{1}".format(start, end - 1))
    return ",".join(parts)


def render_fragment(box: Box, version: int,
                    protocol_names: dict, state_names: dict) -> str:
    """Human readable description of a residual traffic fragment."""
    src_nets = ranges_to_cidrs(box.src_ips, version)
    dst_nets = ranges_to_cidrs(box.dst_ips, version)
    protocols = _format_token_ranges(box.protocols, protocol_names)
    states = _format_token_ranges(box.states, state_names)
    return (
        "src={src} dst={dst} proto={proto} "
        "sport={sport} dport={dport} state={state}"
    ).format(
        src=",".join(str(net) for net in src_nets),
        dst=",".join(str(net) for net in dst_nets),
        proto=protocols,
        sport=_format_ports(box.src_ports),
        dport=_format_ports(box.dst_ports),
        state=states,
    )


def _format_token_ranges(ranges: Sequence[Tuple[int, int]],
                         names: dict) -> str:
    parts = []
    for start, end in ranges:
        for value in range(start, end):
            parts.append(names.get(value, str(value)))
    return ",".join(parts)
