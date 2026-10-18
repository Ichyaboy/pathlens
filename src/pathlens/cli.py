from pathlib import Path
import json
import networkx as nx
import typer
from pydantic import BaseModel, model_validator
from rich.console import Console

app = typer.Typer(help="Explain synthetic Active Directory attack paths.")
console = Console()

class Node(BaseModel):
    id: str
    type: str

class Edge(BaseModel):
    source: str
    target: str
    relation: str

class GraphData(BaseModel):
    nodes: list[Node]
    edges: list[Edge]

    @model_validator(mode="after")
    def check_references(self):
        ids = [n.id for n in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate node IDs")
        for edge in self.edges:
            if edge.source not in ids or edge.target not in ids:
                raise ValueError(f"Unknown node referenced by edge: {edge}")
        return self

EXPLANATIONS = {
    "MemberOf": "Group membership relationship; privileges depend on the group's effective rights.",
    "GenericAll": "Broad control over the target object; practical abuse requires validation.",
    "GenericWrite": "Write permissions on the target object; impact depends on writable attributes.",
    "AddMember": "Potential ability to modify membership of the target group.",
}

@app.command()
def analyze(
    input: Path = typer.Option(..., "--input", exists=True, readable=True),
    source: str = typer.Option(..., "--source"),
    target: str = typer.Option(..., "--target"),
):
    try:
        data = GraphData.model_validate(json.loads(input.read_text(encoding="utf-8")))
    except (ValueError, OSError) as exc:
        console.print(f"[red]Invalid input:[/red] {exc}")
        raise typer.Exit(2)
    graph = nx.MultiDiGraph()
    for node in data.nodes:
        graph.add_node(node.id, type=node.type)
    for edge in data.edges:
        graph.add_edge(edge.source, edge.target, relation=edge.relation)
    if source not in graph or target not in graph:
        console.print("[red]Unknown source or target.[/red]")
        raise typer.Exit(2)
    try:
        path = nx.shortest_path(graph, source, target)
    except nx.NetworkXNoPath:
        console.print("No directed path found.")
        raise typer.Exit(1)
    console.print(f"[bold]PathLens v0.1[/bold] — {len(path)-1} relationships")
    for i, (start, end) in enumerate(zip(path, path[1:]), 1):
        edge = next(iter(graph[start][end].values()))
        relation = edge["relation"]
        console.print(f"[{i}] {start} -> {end} ({relation})")
        console.print(f"    {EXPLANATIONS.get(relation, 'Unsupported relationship; no security conclusion available.')}")
    console.print("[yellow]A graph path is not proof of exploitability.[/yellow]")

if __name__ == "__main__":
    app()
