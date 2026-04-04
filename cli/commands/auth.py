import typer
from rich.console import Console

app = typer.Typer()
console = Console()

@app.command()
def login():
    """Authenticate with the VulnScout Pro backend."""
    console.print("[bold cyan]Authentication Wizard[/]")
    console.print("[yellow]Warning: Running in No-DB mode. Session is ephemeral.[/]")
    
    username = typer.prompt("Username", default="demo@vulnscout.local")
    password = typer.prompt("Password", hide_input=True)
    
    # Mock authentication
    if username == "demo@vulnscout.local":
        console.print(f"[bold green]Login successful for {username}[/]")
    else:
        console.print("[bold red]Authentication failed.[/]")

@app.command()
def logout():
    """Clear local session and tokens."""
    console.print("[bold blue]Session cleared.[/]")

@app.command()
def status():
    """Check current authentication status."""
    console.print("Status: [bold]AUTHENTICATED [dim](Demo Mode)[/][/]")
