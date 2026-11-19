"""Static analyzer for IPv4/IPv6 access control lists.

This package only performs static configuration analysis.  It never emits
or executes any firewall command.
"""

from .analyzer import AnalysisReport, RuleAnalysis, analyze
from .model import Rule
from .parser import parse_rule_text

__all__ = [
    "Rule",
    "RuleAnalysis",
    "AnalysisReport",
    "analyze",
    "parse_rule_text",
]
