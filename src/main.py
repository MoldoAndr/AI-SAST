"""
Main entry point for AI_SAST when run from the command line.
This is a compatibility wrapper that invokes the project orchestrator.
"""

import os
import sys
from pathlib import Path
from rich.console import Console
import pyfiglet

from project_orchestrator import run_orchestrator

def display_banner():
    console = Console()
    banner = pyfiglet.figlet_format("AI_SAST", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold white]AI-Powered Static Application Security Testing[/bold white]")
    console.print("[italic]Scanning projects for security vulnerabilities using GPT-4o[/italic]")
    console.print()

def main():
    display_banner()
    console = Console()
    
    # Check for OpenAI API key
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        console.print("[bold red]ERROR:[/bold red] OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")
        return 1
    
    # Check for project directory structure
    base_dir = Path("/project")
    input_dir = base_dir / "input"
    output_dir = base_dir / "output"
    
    input_dir.mkdir(exist_ok=True, parents=True)
    output_dir.mkdir(exist_ok=True, parents=True)
    
    # Run the orchestrator
    try:
        run_orchestrator(api_key)
        return 0
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
