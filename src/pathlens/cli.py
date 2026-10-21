from pathlib import Path
import json
import networkx as nx
import typer
from rich.console import Console
from pathlens.graph import (
    GraphData, analyze_graph, build_graph,
)
from pathlens.importers.bloodhound import (
    ImportValidationError, read_ce_graph, serialize_graph, write_new_file,
)
from pathlens.reporting import build_report, render_json, render_markdown

app = typer.Typer(help="Explain synthetic Active Directory relationship paths.")
console = Console()
import_app = typer.Typer(help="Normalize supported offline graph exports.")
app.add_typer(import_app, name="import")


@import_app.command("bloodhound")
def import_bloodhound(
    input: Path = typer.Option(..., "--input"),
    format: str = typer.Option("ce-graph", "--format"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Import a CE graph-view JSON export; no directory access or exploitation."""
    if format != "ce-graph":
        typer.echo("Unsupported format; expected ce-graph.", err=True)
        raise typer.Exit(2)
    try:
        result = read_ce_graph(input)
        content = serialize_graph(result.data)
        if output is None:
            typer.echo(content, nl=False)
        else:
            write_new_file(output, content)
    except ImportValidationError as exc:
        typer.echo(f"Invalid import: {exc}", err=True)
        raise typer.Exit(2)
    except OSError as exc:
        typer.echo(f"Import I/O error: {exc}", err=True)
        raise typer.Exit(1)
    for diagnostic in result.diagnostics:
        typer.echo(diagnostic, err=True)
    typer.echo(
        f"Imported {len(result.data.nodes)} nodes and {len(result.data.edges)} relationships.",
        err=True,
    )

@app.callback()
def main() -> None:
    """Explain synthetic Active Directory relationship paths."""

@app.command()
def analyze(
    input: Path = typer.Option(..., "--input", exists=True, readable=True),
    source: str = typer.Option(..., "--source"),
    target: str = typer.Option(..., "--target"),
    format: str = typer.Option("terminal", "--format"),
    output: Path | None = typer.Option(None, "--output"),
):
    if format not in {"terminal", "json", "markdown"}:
        typer.echo("Unsupported format; expected terminal, json, or markdown.", err=True)
        raise typer.Exit(2)
    if output is not None and format == "terminal":
        typer.echo("--output requires --format json or --format markdown.", err=True)
        raise typer.Exit(2)
    error_console = console if format == "terminal" else Console(stderr=True)
    try:
        data = GraphData.model_validate(json.loads(input.read_text(encoding="utf-8")))
    except (ValueError, OSError) as exc:
        error_console.print(f"Invalid input: {exc}", style="red", markup=False)
        raise typer.Exit(2)
    graph = build_graph(data)
    try:
        result = analyze_graph(graph, source, target)
    except nx.NodeNotFound:
        error_console.print("[red]Unknown source or target.[/red]")
        raise typer.Exit(2)
    except nx.NetworkXNoPath:
        error_console.print("No directed path found.")
        raise typer.Exit(1)
    if format != "terminal":
        report = build_report(result)
        content = render_json(report) if format == "json" else render_markdown(report)
        try:
            if output is None:
                typer.echo(content, nl=False)
            else:
                write_new_file(output, content)
        except OSError as exc:
            typer.echo(f"Report I/O error: {exc}", err=True)
            raise typer.Exit(1)
        return
    count = sum(len(hop) for hop in result.relationships)
    console.print(f"[bold]PathLens v0.1[/bold] — {count} relationships")
    for i, relationships in enumerate(result.relationships, 1):
        for report in relationships:
            edge = report.edge
            console.print(
                f"[{i}] {edge.source} -> {edge.target} ({edge.relation})",
                markup=False,
            )
            console.print(f"    {report.explanation}", markup=False)
            if not report.recognized:
                console.print("    Semantics: unknown.", markup=False)
            for implication in report.potential_implications:
                console.print(f"    Potential implication: {implication}", markup=False)
            for warning in report.warnings:
                console.print(f"    Warning: {warning}", markup=False)
            if report.semantics:
                for prerequisite in report.semantics.prerequisites:
                    console.print(f"    Requires validation: {prerequisite}", markup=False)
                for limitation in report.semantics.limitations:
                    console.print(f"    Limitation: {limitation}", markup=False)
                console.print(f"    Remediation: {report.semantics.remediation}", markup=False)
    console.print("Exploitability: not assessed.")
    console.print("[yellow]A graph path is not proof of exploitability.[/yellow]")

if __name__ == "__main__":
    app()
