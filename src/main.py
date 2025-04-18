import os
import sys
import logging
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import pyfiglet
from scanner.file_discovery import discover_relevant_files
from scanner.file_analyzer import analyze_file_relationships
from scanner.vulnerability_detector import scan_files_for_vulnerabilities
from scanner.config import setup_config
from scanner.logger import setup_logger

def display_banner():
    console = Console()
    banner = pyfiglet.figlet_format("AI_SAST", font="slant")
    console.print(Panel.fit(
        f"[bold cyan]{banner}[/bold cyan]\n"
        f"[bold white]AI-Powered Static Application Security Testing[/bold white]\n"
        f"[italic]Scanning frontend code for security vulnerabilities[/italic]",
        border_style="blue"
    ))

def main():
    display_banner()
    console = Console()
    
    try:
        config = setup_config()
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] Failed to setup configuration: {str(e)}")
        sys.exit(1)
    
    logs_folder_name = config.get_logs_folder_name()
    output_subdir = Path(config.output_dir) / logs_folder_name
    output_subdir.mkdir(exist_ok=True, parents=True)
    
    logger = setup_logger(output_subdir, config.log_level)
    logger.info("Starting AI_SAST scan")
    
    scan_start_time = time.time()
    src_dir = Path(config.src_dir)
    
    console.print(f"[bold green]Scanning[/bold green] {project_name}")
    console.print(f"[bold]Source directory:[/bold] {src_dir}")
    console.print(f"[bold]Output directory:[/bold] {output_subdir}")
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            file_discovery_task = progress.add_task("[cyan]Discovering relevant files...", total=100)
            relevant_files = discover_relevant_files(src_dir, progress, file_discovery_task)
            progress.update(file_discovery_task, completed=100)
            
            if not relevant_files:
                console.print("[yellow]Warning: No relevant files found for scanning[/yellow]")
                return
            
            relationship_task = progress.add_task("[cyan]Analyzing file relationships...", total=100)
            file_relationships = analyze_file_relationships(relevant_files, progress, relationship_task)
            progress.update(relationship_task, completed=100)
            
            vuln_task = progress.add_task("[cyan]Scanning for vulnerabilities...", total=len(relevant_files))
            vulnerabilities = scan_files_for_vulnerabilities(
                relevant_files, 
                file_relationships,
                config, 
                progress,
                vuln_task
            )
            progress.update(vuln_task, completed=len(relevant_files))
        
        scan_duration = time.time() - scan_start_time
        files_count = len(relevant_files)
        vuln_count = sum(len(v) for v in vulnerabilities.values())
        
        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print(f"Files scanned: [bold]{files_count}[/bold]")
        console.print(f"Vulnerabilities found: [bold]{vuln_count}[/bold]")
        console.print(f"Scan duration: [bold]{scan_duration:.2f}s[/bold]")
        console.print(f"Results saved to: [bold]{output_subdir}[/bold]")
        
        if vuln_count > 0:
            console.print("\n[bold yellow]Vulnerabilities by type:[/bold yellow]")
            vuln_types = {}
            for file_vulns in vulnerabilities.values():
                for vuln in file_vulns:
                    vtype = vuln.get("vulnerability_type")
                    vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            
            for vtype, count in vuln_types.items():
                console.print(f"  [yellow]{vtype}:[/yellow] {count}")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]ERROR:[/bold red] {str(e)}")
        logger.exception("Error during scan")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
