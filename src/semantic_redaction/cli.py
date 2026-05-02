from __future__ import annotations

from typing import Literal

import typer
from rich.console import Console

from semantic_redaction.models import UseCase
from semantic_redaction.pipeline import LAST_RUN_PATH, PipelineRunner
from semantic_redaction.render import render_result
from semantic_redaction.report import audit_to_markdown, load_last_run

app = typer.Typer(help="Qwen-based Korean financial semantic redaction demo.")
demo_app = typer.Typer(help="Run demo scenarios.")
audit_app = typer.Typer(help="Inspect audit logs.")
app.add_typer(demo_app, name="demo")
app.add_typer(audit_app, name="audit")
console = Console()


def _run_one(usecase: UseCase, model: str, runtime: str) -> None:
    runner = PipelineRunner(model=model, runtime=runtime)
    render_result(console, runner.run(usecase))


@demo_app.command("card")
def demo_card(
    model: str = typer.Option("qwen3:30b-a3b", help="Local Qwen model name."),
    runtime: str = typer.Option("auto", help="auto, ollama, openai-compatible, or mock."),
) -> None:
    _run_one("card", model, runtime)


@demo_app.command("insurance")
def demo_insurance(
    model: str = typer.Option("qwen3:30b-a3b", help="Local Qwen model name."),
    runtime: str = typer.Option("auto", help="auto, ollama, openai-compatible, or mock."),
) -> None:
    _run_one("insurance", model, runtime)


@demo_app.command("debt")
def demo_debt(
    model: str = typer.Option("qwen3:30b-a3b", help="Local Qwen model name."),
    runtime: str = typer.Option("auto", help="auto, ollama, openai-compatible, or mock."),
) -> None:
    _run_one("debt", model, runtime)


@demo_app.command("all")
def demo_all(
    model: str = typer.Option("qwen3:30b-a3b", help="Local Qwen model name."),
    runtime: str = typer.Option("auto", help="auto, ollama, openai-compatible, or mock."),
) -> None:
    for usecase in ("card", "insurance", "debt"):
        _run_one(usecase, model, runtime)


@audit_app.command("last-run")
def audit_last_run(
    format: Literal["md", "json"] = typer.Option("md", "--format", help="Output format."),
) -> None:
    if not LAST_RUN_PATH.exists():
        raise typer.BadParameter("No last-run audit exists. Run a demo first.")
    data = load_last_run()
    if format == "json":
        console.print_json(data=data)
    else:
        console.print(audit_to_markdown(data))
