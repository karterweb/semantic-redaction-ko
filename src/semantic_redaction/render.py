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
    console.print(f"Status: [bold]{result.policy_audit.status}[/bold] | Risk: {result.policy_audit.risk_level}")
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
    console.print(Panel(result.final_response or "-", title="6. Safe Rehydration", border_style="green"))
