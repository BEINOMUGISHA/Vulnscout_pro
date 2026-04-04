import typer
from rich.console import Console
from cli.commands import scan, report, auth

app = typer.Typer(
    name="vulnscout",
    help="VulnScout Pro CLI — High-Velocity Security Intelligence",
    add_completion=True,
)

# Add subcommands
app.add_typer(scan.app, name="scan", help="Initiate and monitor security scans")
app.add_typer(report.app, name="report", help="Manage and export security findings")
app.add_typer(auth.app, name="auth", help="Authentication and session management")

console = Console()

BANNER = """
[bold amber]
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ██║   ██║██║   ██║   ██║   
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██║   ██║██║   ██║   ██║   
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝   
[/][bold blue]                         PRO EDITION | MISSION CRITICAL[/]
"""

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    VulnScout Pro CLI entry point.
    """
    if ctx.invoked_subcommand is None:
        console.print(BANNER)
        console.print("\n[bold cyan]Entering Interactive Mode...[/]\n")
        # Fallback to scan wizard if no command provided
        from cli.commands.scan import wizard
        wizard()

if __name__ == "__main__":
    app()
