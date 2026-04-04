import typer
import asyncio
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import get_config
from storage import get_scan_store_instance

app = typer.Typer()
console = Console()

@app.command()
def list(
    limit: int = typer.Option(10, "--limit", "-l", help="Number of scans to list"),
    json_out: bool = typer.Option(False, "--json", help="Output in machine-readable JSON")
):
    """List recent security scans."""
    store = get_scan_store_instance()
    # list_scans returns (List[dict], total_count)
    scans, _ = asyncio.run(store.list_scans(limit=limit))
    
    if json_out:
        import json
        console.print(json.dumps(scans, indent=2))
        return

    table = Table(title="Recent Security Scans", border_style="blue", box=None, expand=True)
    table.add_column("ID", style="dim")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Date")
    
    for s in scans:
        status_color = "green" if s.get("status") == "complete" else "amber" if s.get("status") == "running" else "red"
        target = s.get("target", {})
        target_url = target.get("url") if isinstance(target, dict) else s.get("target_url", "N/A")
        
        created_at = s.get("created_at", "N/A")
        if isinstance(created_at, str) and "T" in created_at:
             created_at = created_at.split("T")[0]

        table.add_row(
            s.get("id", "N/A")[:8],
            target_url,
            f"[{status_color}]{s.get('status', 'N/A')}[/]",
            str(s.get("metrics", {}).get("total_findings", 0)),
            created_at
        )
    
    console.print(table)

@app.command()
def show(scan_id: str):
    """Show detailed findings for a specific scan."""
    store = get_scan_store_instance()
    scan = asyncio.run(store.get_summary(scan_id))
    if not scan:
        console.print(f"[bold red]Error:[/] Scan {scan_id} not found.")
        raise typer.Exit(code=1)
    
    target = scan.get("target", {})
    target_url = target.get("url") if isinstance(target, dict) else scan.get("target_url", "N/A")
    metrics = scan.get("metrics", {})

    console.print(f"\n[bold amber]Results for:[/] [underline blue]{target_url}[/]")
    console.print(f"[dim]Total Findings: {metrics.get('total_findings', 0)}[/]")
    console.print("[yellow]Detailed finding drill-down via CLI is coming soon![/]")
