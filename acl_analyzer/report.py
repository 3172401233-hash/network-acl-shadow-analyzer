"""Plain text rendering of :class:`AnalysisReport`."""

from .analyzer import AnalysisReport, RuleAnalysis


def _format_cause_list(analysis: RuleAnalysis) -> str:
    if not analysis.shadowed_by:
        return "-"
    return "; ".join(
        "{0}({1})".format(cause.rule_id, cause.action)
        for cause in analysis.shadowed_by
    )


def format_report(report: AnalysisReport) -> str:
    lines = [
        "Static ACL analysis (no firewall commands are generated or executed)",
        "rules analyzed: {0}".format(len(report.rules)),
        "fully shadowed: {0}".format(
            ", ".join(rule.rule_id for rule in report.fully_shadowed_rules)
            or "none"),
        "partially shadowed: {0}".format(
            ", ".join(rule.rule_id
                      for rule in report.partially_shadowed_rules)
            or "none"),
        "redundant: {0}".format(
            ", ".join(rule.rule_id for rule in report.redundant_rules)
            or "none"),
        "action conflicts: {0}".format(
            ", ".join(rule.rule_id for rule in report.conflicting_rules)
            or "none"),
        "",
    ]

    for analysis in report.analyses:
        rule = analysis.rule
        lines.append(
            "[{index}] rule {id} {direction} {action} {src} -> {dst} "
            "status={status}".format(
                index=rule.index,
                id=rule.rule_id,
                direction=rule.direction,
                action=rule.action,
                src=str(rule.src_cidr),
                dst=str(rule.dst_cidr),
                status=analysis.status,
            ))
        if analysis.duplicate_of:
            lines.append("  duplicate of: {0}"
                         .format(", ".join(analysis.duplicate_of)))
        if analysis.shadowed_by:
            lines.append("  shadowed by: {0}"
                         .format(_format_cause_list(analysis)))
        for cause in analysis.redundant_fragments:
            lines.append("  redundant overlap with {0} (same action {1})"
                         .format(cause.rule_id, cause.action))
        for cause in analysis.conflicts:
            lines.append(
                "  action conflict: earlier {0} ({1}) overrides this rule's "
                "{2} on {3} fragment(s)".format(
                    cause.rule_id, cause.action, rule.action,
                    len(cause.fragments)))
        if analysis.effective_boxes:
            lines.append("  remaining traffic:")
            for text in analysis.remaining_fragments_text(
                    report.protocol_names, report.state_names):
                lines.append("    - {0}".format(text))
        else:
            lines.append("  remaining traffic: none (rule never matches)")
    return "\n".join(lines)
