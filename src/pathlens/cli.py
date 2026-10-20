from pathlib import Path
import json
import networkx as nx
import typer
from rich.console import Console
from pathlens.graph import (
    GraphData, analyze_graph, build_graph,
)

app = typer.Typer(help="Explain synthetic Active Directory relationship paths.")
console = Console()

@app.callback()
def main() -> None:
    """Explain synthetic Active Directory relationship paths."""

@app.command()
def analyze(
    input: Path = typer.Option(..., "--input", exists=True, readable=True),
    source: str = typer.Option(..., "--source"),
    target: str = typer.Option(..., "--target"),
):
    try:
        data = GraphData.model_validate(json.loads(input.read_text(encoding="utf-8")))
    except (ValueError, OSError) as exc:
        console.print(f"Invalid input: {exc}", style="red", markup=False)
        raise typer.Exit(2)
    graph = build_graph(data)
    try:
        result = analyze_graph(graph, source, target)
    except nx.NodeNotFound:
        console.print("[red]Unknown source or target.[/red]")
        raise typer.Exit(2)
    except nx.NetworkXNoPath:
        console.print("No directed path found.")
        raise typer.Exit(1)
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
