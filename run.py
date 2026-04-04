"""
vulnscout_pro/run.py — Application Launcher

Provides a single entry point for launching the Web Dashboard, API, or CLI.
Ensures the project root is in PYTHONPATH and environment is ready.

Usage:
    python run.py web       # Launch Web Dashboard (Uvicorn)
    python run.py api       # Alias for web
    python run.py cli ...   # Launch CLI
"""

import sys
import os
import subprocess
from pathlib import Path

# Add project root to PYTHONPATH
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

def run_web():
    """Launch the FastAPI application with Uvicorn."""
    print("Launching VulnScout Pro Web Dashboard...")
    try:
        import uvicorn
        uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
    except ImportError:
        print("Error: uvicorn not installed. Run 'pip install -r requirements/base.txt'")
        sys.exit(1)

def run_cli():
    """Launch the CLI application."""
    from cli.main import app
    app()

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py [web|cli] [args...]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd in ("web", "api"):
        run_web()
    elif cmd == "cli":
        # Pass remaining args to CLI
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        run_cli()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
