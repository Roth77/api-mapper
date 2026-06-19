"""
apimapper CLI.

    apimapper init-scope                       # create a scope.yaml template
    apimapper scan-web ./dist --scope scope.yaml -o report.md
    apimapper scan-apk ./app.apk --scope scope.yaml -o report.md
    apimapper scan-web ./dist --scope scope.yaml --no-active --no-agent -o report.json
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from apimapper.core.orchestrator import run_web_scan, run_android_scan
from apimapper.core.scope import DEFAULT_SCOPE_TEMPLATE, ScopeError, ScopeGuard
from apimapper.reporting.report import write_report

app = typer.Typer(add_completion=False, help="Authorized red-team API endpoint & secret mapper.")
console = Console()


@app.command()
def init_scope(path: str = typer.Option("scope.yaml", help="Where to write the scope template")):
    """Create a scope.yaml template. Edit it before running any active scan."""
    p = Path(path)
    if p.exists():
        console.print(f"[yellow]{path} already exists — not overwriting.[/yellow]")
        raise typer.Exit(1)
    p.write_text(DEFAULT_SCOPE_TEMPLATE)
    console.print(f"[green]Wrote {path}.[/green] Edit it and set allow_active_probing: true when ready.")


def _print_summary(scan):
    s = scan.summary()
    table = Table(title=f"Scan summary — {scan.target}")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for k, v in s.items():
        table.add_row(k, str(v))
    console.print(table)


def _maybe_run_agent(scan, use_agent: bool):
    if not use_agent:
        return None
    from apimapper.agent.reasoning import run_agent_analysis, AgentReasoningError
    try:
        console.print("[cyan]Running agent analysis...[/cyan]")
        return run_agent_analysis(scan)
    except AgentReasoningError as e:
        console.print(f"[yellow]Agent analysis skipped: {e}[/yellow]")
        return None


@app.command()
def scan_web(
    js_path: str = typer.Argument(..., help="Path to a JS file or directory of bundled JS"),
    scope: str = typer.Option(..., "--scope", "-s", help="Path to scope.yaml"),
    base_host: str = typer.Option(None, help="Base host to attach to relative paths, e.g. https://api.example.com"),
    active: bool = typer.Option(True, "--active/--no-active", help="Attempt live probing of in-scope endpoints"),
    agent: bool = typer.Option(True, "--agent/--no-agent", help="Run LLM clustering/prioritization pass"),
    out: str = typer.Option("apimapper_report.md", "--out", "-o", help="Output path (.md or .json)"),
):
    """Static-extract + (optionally) probe endpoints found in JS source/bundles."""
    try:
        scan = run_web_scan(js_path, scope, do_active_probe=active, base_host_hint=base_host)
    except ScopeError as e:
        console.print(f"[red]Scope error: {e}[/red]")
        raise typer.Exit(1)

    scan.finished_at = datetime.now(timezone.utc).isoformat()
    _print_summary(scan)
    analysis = _maybe_run_agent(scan, agent)
    out_path = write_report(scan, out, analysis)
    console.print(f"[green]Report written to {out_path}[/green]")


@app.command()
def scan_apk(
    apk_path: str = typer.Argument(..., help="Path to the .apk file"),
    scope: str = typer.Option(..., "--scope", "-s", help="Path to scope.yaml"),
    active: bool = typer.Option(True, "--active/--no-active", help="Attempt live probing of in-scope endpoints"),
    agent: bool = typer.Option(True, "--agent/--no-agent", help="Run LLM clustering/prioritization pass"),
    out: str = typer.Option("apimapper_report.md", "--out", "-o", help="Output path (.md or .json)"),
):
    """Decompile an APK and static-extract + (optionally) probe discovered endpoints."""
    try:
        scan = run_android_scan(apk_path, scope, do_active_probe=active)
    except ScopeError as e:
        console.print(f"[red]Scope error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    scan.finished_at = datetime.now(timezone.utc).isoformat()
    _print_summary(scan)
    analysis = _maybe_run_agent(scan, agent)
    out_path = write_report(scan, out, analysis)
    console.print(f"[green]Report written to {out_path}[/green]")


@app.command()
def discover_paths(
    base_host: str = typer.Argument(..., help="In-scope base host to probe, e.g. https://api.example.com"),
    scope: str = typer.Option(..., "--scope", "-s", help="Path to scope.yaml"),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help="Custom wordlist path (default: built-in common paths)"),
    out: str = typer.Option("apimapper_discovery.md", "--out", "-o", help="Output path (.md or .json)"),
):
    """Probe a single in-scope host with a wordlist of common API paths to find undocumented endpoints."""
    import asyncio
    from apimapper.core.scope import Scope
    from apimapper.probes.wordlist_probe import discover_via_wordlist
    from apimapper.core.models import ScanResult

    try:
        scope_obj = Scope.load(scope)
        guard = ScopeGuard(scope_obj)
        found = asyncio.run(discover_via_wordlist(base_host, guard, wordlist_path=wordlist))
    except ScopeError as e:
        console.print(f"[red]Scope error: {e}[/red]")
        raise typer.Exit(1)

    scan = ScanResult(target=base_host, target_type="wordlist_discovery")
    scan.endpoints = found
    scan.scope_engagement = scope_obj.engagement_name
    scan.finished_at = datetime.now(timezone.utc).isoformat()

    _print_summary(scan)
    out_path = write_report(scan, out)
    console.print(f"[green]Found {len(found)} non-404 paths. Report written to {out_path}[/green]")


if __name__ == "__main__":
    app()
