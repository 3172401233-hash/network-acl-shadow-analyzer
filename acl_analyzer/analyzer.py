"""Ordered ACL shadow / conflict / redundancy analysis.

Rules are processed strictly in configuration order inside each traffic
direction.  Every rule owns the part of its matching box that no earlier
rule in the same direction already claimed.  Rules are never reordered by
prefix length, so configuration order drives every result.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .model import (
    PROTOCOL_NUMBERS,
    STATE_NUMBERS,
    Rule,
    RuleInputError,
)
from .space import (
    Box,
    merge_adjacent_boxes,
    render_fragment,
    subtract_boxes,
)

DEFAULT_PROTOCOL_UNIVERSE = {
    number for number in PROTOCOL_NUMBERS.values() if number is not None
}
DEFAULT_STATE_UNIVERSE = set(STATE_NUMBERS.values())


def _singleton_ranges(numbers: Sequence[int]) -> tuple:
    return tuple((number, number + 1) for number in numbers)


@dataclass
class CoveredFragment:
    """A piece of traffic already claimed by an earlier rule."""

    box: Box
    rule_id: str
    action: str


@dataclass
class ShadowCause:
    """Why part (or all) of a rule was taken by an earlier rule."""

    rule_id: str
    action: str
    fragments: List[Box] = field(default_factory=list)


@dataclass
class RuleAnalysis:
    rule: Rule
    effective_boxes: List[Box]
    shadowed_by: List[ShadowCause]
    redundant_fragments: List[ShadowCause]
    conflicts: List[ShadowCause]
    duplicate_of: List[str]

    @property
    def fully_shadowed(self) -> bool:
        return not self.effective_boxes

    @property
    def partially_shadowed(self) -> bool:
        return bool(self.shadowed_by) and bool(self.effective_boxes)

    @property
    def is_redundant(self) -> bool:
        return self.fully_shadowed and all(
            cause.action == self.rule.action
            for cause in self.shadowed_by
        )

    @property
    def status(self) -> str:
        if self.fully_shadowed:
            return "fully_shadowed"
        if self.partially_shadowed:
            return "partially_shadowed"
        return "active"

    def remaining_fragments_text(
        self, protocol_names: Dict[int, str], state_names: Dict[int, str]
    ) -> List[str]:
        return [
            render_fragment(box, self.rule.version,
                            protocol_names, state_names)
            for box in self.effective_boxes
        ]


@dataclass
class AnalysisReport:
    rules: List[Rule]
    analyses: List[RuleAnalysis]
    protocol_names: Dict[int, str]
    state_names: Dict[int, str]

    @property
    def fully_shadowed_rules(self) -> List[Rule]:
        return [item.rule for item in self.analyses if item.fully_shadowed]

    @property
    def partially_shadowed_rules(self) -> List[Rule]:
        return [item.rule for item in self.analyses if item.partially_shadowed]

    @property
    def redundant_rules(self) -> List[Rule]:
        return [item.rule for item in self.analyses if item.is_redundant]

    @property
    def conflicting_rules(self) -> List[Rule]:
        return [item.rule for item in self.analyses if item.conflicts]


def _build_universes(rules: Sequence[Rule]):
    protocols = set(DEFAULT_PROTOCOL_UNIVERSE)
    states = set(DEFAULT_STATE_UNIVERSE)
    for rule in rules:
        protocols.update(rule.protocol)
        states.update(rule.states)
    return sorted(protocols), sorted(states)


def _build_box(rule: Rule, protocol_universe: Sequence[int],
               state_universe: Sequence[int]) -> Box:
    protocols = rule.protocol or protocol_universe
    states = rule.states or state_universe
    return Box(
        src_ips=(rule.cidr_interval(rule.src_cidr),),
        dst_ips=(rule.cidr_interval(rule.dst_cidr),),
        protocols=_singleton_ranges(protocols),
        src_ports=tuple(rule.src_ports),
        dst_ports=tuple(rule.dst_ports),
        states=_singleton_ranges(states),
    )


def _record_cause(causes: Dict[str, ShadowCause], fragment: CoveredFragment,
                  piece: Box) -> None:
    cause = causes.get(fragment.rule_id)
    if cause is None:
        cause = ShadowCause(fragment.rule_id, fragment.action)
        causes[fragment.rule_id] = cause
    cause.fragments.append(piece)


def _analyze_group(rules: Sequence[Rule], protocol_universe: Sequence[int],
                   state_universe: Sequence[int]) -> Dict[str, RuleAnalysis]:
    covered: List[CoveredFragment] = []
    results: Dict[str, RuleAnalysis] = {}

    for rule in rules:
        box = _build_box(rule, protocol_universe, state_universe)
        residual: List[Box] = [box]
        causes: Dict[str, ShadowCause] = {}

        for fragment in covered:
            next_residual: List[Box] = []
            for piece in residual:
                overlap = piece.intersect(fragment.box)
                if overlap is not None:
                    _record_cause(causes, fragment, overlap)
                next_residual.extend(piece.subtract(fragment.box))
            residual = next_residual
        residual = merge_adjacent_boxes(residual)

        shadowed_by = list(causes.values())
        for cause in shadowed_by:
            cause.fragments = merge_adjacent_boxes(cause.fragments)
        redundant = [cause for cause in shadowed_by
                     if cause.action == rule.action]
        conflicts = [cause for cause in shadowed_by
                     if cause.action != rule.action]
        duplicate_of = [
            cause.rule_id for cause in shadowed_by
            if len(cause.fragments) == 1 and cause.fragments[0] == box
        ]

        results[rule.rule_id] = RuleAnalysis(
            rule=rule,
            effective_boxes=residual,
            shadowed_by=shadowed_by,
            redundant_fragments=redundant,
            conflicts=conflicts,
            duplicate_of=duplicate_of,
        )
        covered.append(CoveredFragment(box, rule.rule_id, rule.action))

    return results


def analyze(rules: Sequence[Rule]) -> AnalysisReport:
    """Analyze an ordered rule list and return a structured report."""
    indexed: List[Rule] = []
    seen_ids = set()
    for index, rule in enumerate(rules):
        if rule.rule_id in seen_ids:
            raise RuleInputError(
                "duplicate rule_id: {0!r}".format(rule.rule_id))
        seen_ids.add(rule.rule_id)
        rule.index = index
        indexed.append(rule)

    protocol_universe, state_universe = _build_universes(indexed)
    protocol_names = {
        number: name for name, number in PROTOCOL_NUMBERS.items()
        if number is not None
    }
    state_names = {number: name for name, number in STATE_NUMBERS.items()}

    groups: Dict[str, List[Rule]] = {}
    for rule in indexed:
        groups.setdefault(rule.direction, []).append(rule)

    analyses_by_id: Dict[str, RuleAnalysis] = {}
    for group in groups.values():
        analyses_by_id.update(
            _analyze_group(group, protocol_universe, state_universe))

    analyses = [analyses_by_id[rule.rule_id] for rule in indexed]
    return AnalysisReport(
        rules=indexed,
        analyses=analyses,
        protocol_names=protocol_names,
        state_names=state_names,
    )
