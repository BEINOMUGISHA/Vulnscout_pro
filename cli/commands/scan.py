import typer
import asyncio
from typing import List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from config import get_config
from core.scanner.orchestrator import ScanOrchestrator
from core.models.target import Target
from core.models.scan import Scan, ScanPhase

app = typer.Typer()
console = Console()

@app.command()
def run(
    url: str = typer.Argument(..., help="Target URL to scan"),
    modules: Optional[List[str]] = typer.Option(None, "--module", "-m", help="Specific modules to run"),
    export: Optional[str] = typer.Option(None, "--export", "-e", help="Export format (json, csv, pdf, sarif)"),
    turbo: bool = typer.Option(False, "--turbo", help="Enable high-concurrency engine"),
    unthrottled: bool = typer.Option(False, "--unthrottled", help="Bypass all rate limiting"),
    ci: bool = typer.Option(False, "--ci", help="CI/CD mode (exit code based on findings)")
):
    """Start a new security scan."""
    asyncio.run(_run_scan_logic(url, modules, export, turbo, unthrottled, ci))

@app.command()
def wizard():
    """Interactive scan configuration wizard."""
    console.print("\n[bold cyan]Scan Configuration Wizard[/]")
    
    url = Prompt.ask("[bold white]Enter Target URL[/]", default="http://localhost:3000")
    if not url.startswith("http"):
         url = f"http://{url}"
         
    config = get_config()
    modules = Prompt.ask(
        "[bold white]Modules to run[/] (comma separated)", 
        default=",".join(config.scan.enabled_checks)
    ).split(",")
    
    turbo = Confirm.ask("[bold white]Enable Turbo Mode (High Concurrency)?[/]", default=False)
    
    export = None
    if Confirm.ask("[bold white]Generate report on completion?[/]"):
        export = Prompt.ask("[bold white]Format[/]", choices=["pdf", "json", "csv"], default="pdf")

    asyncio.run(_run_scan_logic(url, [m.strip() for m in modules], export, turbo=turbo))

async def _run_scan_logic(url: str, modules: Optional[List[str]], export: Optional[str], turbo: bool, unthrottled: bool = False, ci: bool = False):
    console.print(f"\n[bold amber]Scouting Target:[/] [underline blue]{url}[/]")
    
    target = Target.from_url(url)
    if modules:
        target.scan_config.enabled_checks = modules
    
    target.scan_config.high_concurrency = turbo
    target.scan_config.unthrottled = unthrottled

    orchestrator = ScanOrchestrator(config=target.scan_config)
    scan_id = orchestrator.scan_id
    console.print(f"[dim]Scan ID: {scan_id}[/]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, pulse_style="amber"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True
    ) as progress:
        
        task_id = progress.add_task("[amber]Initializing Engine...", total=100)
        scan_coro = orchestrator.run(target)
        scan_task = asyncio.create_task(scan_coro)
        
        while not scan_task.done():
            await asyncio.sleep(0.5)
            p = orchestrator.progress
            
            # Map phase to progress
            progress_val = 0
            if p.phase == ScanPhase.CRAWLING:
                progress_val = min(20, p.total_endpoints * 2) 
            elif p.phase in (ScanPhase.DETECTING, ScanPhase.VALIDATING):
                if p.total_endpoints > 0:
                    ratio = p.scanned_endpoints / p.total_endpoints
                    progress_val = 20 + int(ratio * 70)
                else:
                    progress_val = 20
            elif p.phase == ScanPhase.COMPLETE:
                progress_val = 100
            
            status_text = f"[amber]{p.phase.upper()}[/] [dim]|[/] [cyan]Endpoints:[/] {p.scanned_endpoints}/{p.total_endpoints} [dim]|[/] [red]{p.findings_count} findings[/]"
            progress.update(task_id, completed=progress_val, description=status_text)

        result = await scan_task
        scan = Scan.from_dict(result)

    _show_dashboard(scan)
    
    if ci:
        _handle_ci_logic(scan)
    if export:
        await _handle_export_logic(scan, export)

def _show_dashboard(scan: Scan):
    table = Table(title="Security Findings Dashboard", border_style="blue", box=None, expand=True)
    table.add_column("Severity", width=12)
    table.add_column("Vulnerability Type")
    table.add_column("Impact (EA Context)")
    
    for finding in scan.findings:
        color = "red" if finding.severity == "critical" else "orange3" if finding.severity == "high" else "yellow"
        table.add_row(f"[{color}]{finding.severity.upper()}[/]", finding.vuln_type, "N/A")
    
    console.print(Panel(table, border_style="blue"))

def _handle_ci_logic(scan: Scan):
    criticals = [f for f in scan.findings if f.severity == "critical"]
    highs = [f for f in scan.findings if f.severity == "high"]
    if criticals or highs:
        console.print("\n[bold red]❌ CI/CD GATE FAILED[/]")
        raise typer.Exit(code=1)
    console.print("\n[bold green]✅ CI/CD GATE PASSED[/]")

async def _handle_export_logic(scan: Scan, format: str):
    from reporting.builder import ReportBuilder
    builder = ReportBuilder(scan.id)
    path = await builder.generate_report(format)
    console.print(f"\n[bold green]📁 Report generated at:[/] [underline blue]{path}[/]")
