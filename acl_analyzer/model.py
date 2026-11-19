"""Rule model and input normalization."""

from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any, List, Optional, Sequence, Tuple

from .space import FULL_PORT, PortRange, merge_ranges

PROTOCOL_NUMBERS = {
    "any": None,  # marker: expand against the rule-set universe
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "icmpv6": 58,
    "sctp": 132,
}

STATE_NUMBERS = {
    "new": 1,
    "established": 2,
    "related": 3,
    "invalid": 4,
}


class RuleInputError(ValueError):
    """Raised when a rule cannot be parsed or fails validation."""


def normalize_action(action: str) -> str:
    value = str(action).strip().lower().replace("-", "_")
    aliases = {
        "allow": "allow",
        "permit": "allow",
        "accept": "allow",
        "pass": "allow",
        "deny": "deny",
        "drop": "deny",
        "block": "deny",
        "reject": "deny",
    }
    if value not in aliases:
        raise RuleInputError("unsupported action: {0!r}".format(action))
    return aliases[value]


def normalize_direction(direction: str) -> str:
    value = str(direction).strip().lower()
    if value not in ("in", "out"):
        raise RuleInputError("direction must be 'in' or 'out', got {0!r}"
                             .format(direction))
    return value


def normalize_cidr(value: Any) -> Any:
    if isinstance(value, (IPv4Network, IPv6Network)):
        return value
    try:
        return ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise RuleInputError("invalid CIDR {0!r}: {1}".format(value, exc))


def normalize_ports(value: Any) -> List[PortRange]:
    """Accept None/'any', int, 'a-b', lists of those; half-open ranges."""
    if value is None:
        return [FULL_PORT]
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("any", "*", ""):
            return [FULL_PORT]
        tokens = text.split(",")
    elif isinstance(value, tuple) and len(value) == 2 and all(
            isinstance(item, int) for item in value):
        tokens = [value]
    elif isinstance(value, (list, tuple)):
        tokens = list(value)
    else:
        tokens = [value]

    ranges: List[PortRange] = []
    for token in tokens:
        if isinstance(token, (list, tuple)) and len(token) == 2:
            start, end = token
            # Tuple ports are inclusive endpoints, e.g. (0, 65535) == all.
            start, end = int(start), int(end) + 1
        else:
            text = str(token).strip().lower()
            if text in ("any", "*"):
                return [FULL_PORT]
            if "-" in text:
                start_text, end_text = text.split("-", 1)
                start, end = int(start_text), int(end_text)
            else:
                start = end = int(text)
        if not 0 <= start <= end <= 65535:
            raise RuleInputError("port out of range: {0!r}".format(token))
        ranges.append((start, end + 1))
    return merge_ranges(ranges)


def normalize_protocol(value: Any) -> List[int]:
    if value is None:
        return []  # "any", expanded later against the universe
    if isinstance(value, int):
        if not 0 <= value <= 255:
            raise RuleInputError("protocol number out of range: {0}".format(value))
        return [value]
    text = str(value).strip().lower()
    if text in ("any", "*", "all", ""):
        return []
    result: List[int] = []
    for token in text.split(","):
        token = token.strip()
        if token in PROTOCOL_NUMBERS and PROTOCOL_NUMBERS[token] is not None:
            result.append(PROTOCOL_NUMBERS[token])
        elif token.isdigit():
            number = int(token)
            if not 0 <= number <= 255:
                raise RuleInputError("protocol number out of range: {0}"
                                     .format(token))
            result.append(number)
        else:
            raise RuleInputError("unknown protocol: {0!r}".format(token))
    return sorted(set(result))


def normalize_states(value: Any) -> List[int]:
    if value is None:
        return []  # "any state", expanded against the universe
    if isinstance(value, int):
        return [value]
    if isinstance(value, (list, tuple)):
        tokens = value
    else:
        tokens = str(value).split(",")
    result: List[int] = []
    for token in tokens:
        if isinstance(token, int):
            result.append(token)
            continue
        text = str(token).strip().lower()
        if text in ("any", "*", "all", ""):
            return []
        if text in STATE_NUMBERS:
            result.append(STATE_NUMBERS[text])
        elif text.isdigit():
            result.append(int(text))
        else:
            raise RuleInputError("unknown state flag: {0!r}".format(token))
    return sorted(set(result))


@dataclass
class Rule:
    """One ordered access control entry.

    Args are normalized so the analyzer only deals with validated data.
    """

    rule_id: str
    direction: str
    src_cidr: Any
    dst_cidr: Any
    protocol: Any = None
    dst_ports: Any = None
    src_ports: Any = None
    action: str = "deny"
    states: Any = None
    comment: str = ""
    index: int = field(default=-1, compare=False)

    def __post_init__(self) -> None:
        if not str(self.rule_id):
            raise RuleInputError("rule_id must be a non-empty string")
        self.direction = normalize_direction(self.direction)
        self.action = normalize_action(self.action)
        self.src_cidr = normalize_cidr(self.src_cidr)
        self.dst_cidr = normalize_cidr(self.dst_cidr)
        if self.src_cidr.version != self.dst_cidr.version:
            raise RuleInputError(
                "rule {0}: source and destination IP versions must match"
                .format(self.rule_id))
        self.protocol = normalize_protocol(self.protocol)
        self.states = normalize_states(self.states)
        self.src_ports = normalize_ports(self.src_ports)
        self.dst_ports = normalize_ports(self.dst_ports)

    @property
    def version(self) -> int:
        return self.src_cidr.version

    def cidr_interval(self, network: Any) -> PortRange:
        return (int(network.network_address),
                int(network.broadcast_address) + 1)
