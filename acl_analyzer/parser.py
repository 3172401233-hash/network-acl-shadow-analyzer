"""Convenience parser for line oriented ACL text.

Line format (``#`` starts comments, blank lines are ignored)::

    id direction action src CIDR -> dst CIDR [protocol] [dports] [sports] [states]

Only the first five fields are required.  Examples::

    10 in deny 10.0.0.0/24 -> 0.0.0.0/0 tcp 80,443
    20 out allow 2001:db8::/32 -> ::/0 any any any new,established
"""

from typing import List, Optional

from .model import Rule, RuleInputError


def parse_rule_text(text: str) -> List[Rule]:
    rules: List[Rule] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5 or "->" not in parts:
            raise RuleInputError(
                "line {0}: expected "
                "'id direction action src-cidr -> dst-cidr [proto] "
                "[dports] [sports] [states]'".format(line_number))

        arrow = parts.index("->")
        if arrow != 4 or len(parts) < 6:
            raise RuleInputError(
                "line {0}: '->' must separate source and destination"
                .format(line_number))

        rule_id, direction, action, src_cidr, _, dst_cidr = parts[:6]
        extras = parts[6:]
        protocol: Optional[str] = extras[0] if len(extras) > 0 else None
        dst_ports = extras[1] if len(extras) > 1 else None
        src_ports = extras[2] if len(extras) > 2 else None
        states = extras[3] if len(extras) > 3 else None

        rules.append(Rule(
            rule_id=rule_id,
            direction=direction,
            action=action,
            src_cidr=src_cidr,
            dst_cidr=dst_cidr,
            protocol=protocol,
            dst_ports=dst_ports,
            src_ports=src_ports,
            states=states,
            comment=raw_line.strip(),
        ))
    return rules
