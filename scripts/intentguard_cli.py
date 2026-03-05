from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from intentguard import __version__
from intentguard.context.models import load_context
from intentguard.llm.extraction_models import ExtractedIntent
from intentguard.pipeline.compile import compile_intentguard
from intentguard.validate.validators import ValidationError


app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


@app.callback()
def _root() -> None:
    """IntentGuard CLI (academic prototype)."""


@app.command()
def version() -> None:
    """Print IntentGuard version."""
    console.print(__version__)


@app.command()
def compile(
    nl: str = typer.Argument(..., help="Natural language firewall intent."),
    context: Path = typer.Option(
        Path("contexts/example/context.yaml"), "--context", "-c", exists=True, dir_okay=False
    ),
    gemini_model: str = typer.Option("gemini-2.5-flash", "--model"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write JSON result to file."),
    extracted_json: Optional[Path] = typer.Option(
        None,
        "--extracted-json",
        exists=True,
        dir_okay=False,
        help="Skip live Gemini call; use this extracted JSON instead (for offline demos).",
    ),
    format: str = typer.Option(
        "pretty",
        "--format",
        help="Output format: pretty (default) or json.",
    ),
):
    """Compile NL intent into validated IR and iptables commands."""
    ctx = load_context(str(context))
    extracted_override = None
    if extracted_json is not None:
        extracted_override = ExtractedIntent.model_validate_json(
            extracted_json.read_text(encoding="utf-8")
        )
    try:
        res = compile_intentguard(
            nl_policy=nl,
            ctx=ctx,
            gemini_model=gemini_model,
            extracted_override=extracted_override,
        )
    except ValidationError as e:
        payload = {
            "ok": False,
            "issues": [i.__dict__ for i in e.issues],
        }
        text = json.dumps(payload, indent=2)
        if format == "pretty":
            console.print(Panel(Syntax(text, "json", word_wrap=True), title="IntentGuard: Validation Failed"))
        else:
            typer.echo(text)
        raise typer.Exit(code=2)
    except RuntimeError as e:
        # e.g., Gemini quota/rate-limit exceeded
        msg = {"ok": False, "error": str(e)}
        text = json.dumps(msg, indent=2)
        if format == "pretty":
            console.print(Panel(Syntax(text, "json", word_wrap=True), title="IntentGuard: Runtime Error"))
        else:
            typer.echo(text)
        raise typer.Exit(code=3)

    payload = {
        "ok": True,
        "extracted": res.extracted,
        "ir": res.ir.model_dump(),
        "validation": [i.__dict__ for i in res.validation],
        "iptables_commands": res.iptables.commands,
        "iptables_shell": res.iptables.as_shell_lines(),
    }
    text = json.dumps(payload, indent=2)
    if out:
        out.write_text(text, encoding="utf-8")
    if format != "pretty":
        typer.echo(text)
        return

    console.print(Panel(f"[bold]Intent[/bold]: {nl}", title="Stage 0: Input"))
    console.print(
        Panel(
            Syntax(json.dumps(payload["extracted"], indent=2), "json", word_wrap=True),
            title="Stage 1: Gemini Extracted JSON (schema-bound)",
        )
    )
    console.print(
        Panel(
            Syntax(json.dumps(payload["ir"], indent=2), "json", word_wrap=True),
            title="Stage 2: Canonical IR",
        )
    )
    console.print(
        Panel(
            Syntax(json.dumps(payload["validation"], indent=2), "json", word_wrap=True),
            title="Stage 3: Validation Findings",
        )
    )
    console.print(Panel("\n".join(payload["iptables_shell"]), title="Stage 4: iptables Commands (shell)"))
    if out:
        console.print(f"Wrote full JSON artifact to: {out}")


if __name__ == "__main__":
    app()

