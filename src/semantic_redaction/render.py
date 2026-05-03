from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from semantic_redaction.models import PipelineResult


def render_result(console: Console, result: PipelineResult) -> None:
    console.rule(f"[bold]{result.case.title}[/bold]")
    console.print(Panel(result.case.utterance, title="1. Private Raw Input", border_style="red"))
    console.print(
        Panel(
            Syntax(
                json.dumps(result.case.private_records, ensure_ascii=False, indent=2),
                "json",
                word_wrap=True,
            ),
            title="Private Records",
            border_style="red",
        )
    )
    console.print(
        Panel(
            Syntax(result.qwen_draft.model_dump_json(indent=2), "json", word_wrap=True),
            title=f"2. Local Qwen Semantic Redactor ({result.runtime})",
            border_style="yellow",
        )
    )

    table = Table(title="3. Policy & Privacy Gate")
    table.add_column("Severity")
    table.add_column("Reason")
    table.add_column("Path")
    table.add_column("Value")
    if result.policy_audit.findings:
        for finding in result.policy_audit.findings:
            table.add_row(finding.severity, finding.reason, finding.path, finding.value)
    else:
        table.add_row("low", "no_findings", "$", "-")
    console.print(table)
    console.print(
        f"Status: [bold]{result.policy_audit.status}[/bold]"
        f" | Risk: {result.policy_audit.risk_level}"
        f" | Utility Score: {result.policy_audit.utility_score:.2f}"
    )
    console.print(
        Panel(
            "\n".join(result.policy_audit.techniques_applied) or "-",
            title="Meaning-Preserving Techniques",
            border_style="magenta",
        )
    )

    if result.external_payload:
        console.print(
            Panel(
                Syntax(result.external_payload.model_dump_json(indent=2), "json", word_wrap=True),
                title="4. External LLM Payload",
                border_style="green",
            )
        )
    else:
        console.print(Panel("blocked_privacy_risk", title="4. External LLM Payload", border_style="red"))

    console.print(Panel(result.external_response or "-", title="5. Mock External LLM Response", border_style="blue"))

    # Outbound findings
    if result.policy_audit.outbound_findings:
        out_table = Table(title="5a. Outbound Filter Findings (sanitized before rehydration)")
        out_table.add_column("Severity")
        out_table.add_column("Reason")
        out_table.add_column("Value")
        for f in result.policy_audit.outbound_findings:
            out_table.add_row(f.severity, f.reason, f.value)
        console.print(out_table)

    console.print(Panel(result.final_response or "-", title="6. Safe Rehydration", border_style="green"))

    # Privacy audit summary
    audit = result.policy_audit
    tier = audit.risk_tier_assessment
    console.print(
        Panel(
            f"Tier: [bold]{tier.tier.upper()}[/bold]\n"
            f"Rationale: {tier.rationale}\n"
            f"Reviewer count required: {tier.reviewer_count_required}\n"
            f"Reference: {tier.guideline_reference}",
            title="7. Privacy Audit — 2026 Risk Tier Assessment",
            border_style="red" if tier.tier == "high" else "yellow",
        )
    )

    # Cross-reference warnings
    if audit.cross_reference_warnings:
        for warning in audit.cross_reference_warnings:
            console.print(
                Panel(
                    f"Level: [bold]{warning.level.upper()}[/bold]\n"
                    f"Cumulative dimensions: {warning.cumulative_dimension_count}\n"
                    f"Overlapping: {', '.join(warning.overlapping_dimensions) or '-'}\n"
                    f"{warning.description}",
                    title="⚠ Cross-Reference Warning",
                    border_style="yellow",
                )
            )
