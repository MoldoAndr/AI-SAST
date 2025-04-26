"""
Project Orchestrator for AI_SAST.

Handles scanning multiple projects from input folder to output folder with pricing tracking.
"""

import os
import sys
import time
import json
import logging
import shutil
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from scanner.config import Config, setup_config
from scanner.file_discovery import discover_relevant_files
from scanner.file_analyzer import analyze_file_relationships
from scanner.vulnerability_detector import scan_files_for_vulnerabilities
from scanner.logger import setup_logger
from scanner.pricing_tracker import PricingTracker, update_global_pricing

console = Console()

def scan_single_project(project_dir: Path, output_dir: Path, config: Config, pricing_tracker: PricingTracker) -> Dict[str, Any]:
    """
    Scan a single project directory for vulnerabilities.
    
    Args:
        project_dir: Path to the project directory
        output_dir: Path to the output directory
        config: Configuration for the scan
        pricing_tracker: Tracker for token usage and pricing
        
    Returns:
        Dict[str, Any]: Scan results
    """
    project_name = project_dir.name
    console.print(f"[bold blue]Starting scan for project:[/bold blue] {project_name}")
    
    # Create project-specific logger
    project_output_dir = output_dir / project_name
    project_output_dir.mkdir(exist_ok=True, parents=True)
    
    logger = setup_logger(project_output_dir, config.log_level)
    logger.info(f"Starting scan for project: {project_name}")
    
    scan_start_time = time.time()
    
    scan_results = {
        "project_name": project_name,
        "scan_time": datetime.now().isoformat(),
        "token_usage": {
            "input_tokens": 0,
            "output_tokens": 0,
            "cost": 0.0
        },
        "vulnerabilities": [],
        "successful": False,
        "error": None
    }
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            file_discovery_task = progress.add_task(f"[cyan]Discovering relevant files in {project_name}...", total=100)
            relevant_files = discover_relevant_files(project_dir, progress, file_discovery_task)
            progress.update(file_discovery_task, completed=100)
            
            if not relevant_files:
                logger.warning(f"No relevant files found in project {project_name}")
                console.print(f"[yellow]Warning: No relevant files found in project {project_name}[/yellow]")
                scan_results["error"] = "No relevant files found"
                return scan_results
            
            relationship_task = progress.add_task(f"[cyan]Analyzing file relationships in {project_name}...", total=100)
            file_relationships = analyze_file_relationships(relevant_files, progress, relationship_task)
            progress.update(relationship_task, completed=100)
            
            vuln_task = progress.add_task(f"[cyan]Scanning {project_name} for vulnerabilities...", total=len(relevant_files))
            vulnerabilities = scan_files_for_vulnerabilities(
                relevant_files, 
                file_relationships,
                config, 
                progress,
                vuln_task,
                pricing_tracker
            )
            progress.update(vuln_task, completed=len(relevant_files))
        
        # Collect all vulnerabilities
        all_vulns = []
        for file_vulns in vulnerabilities.values():
            all_vulns.extend(file_vulns)
        
        scan_results["vulnerabilities"] = all_vulns
        scan_results["token_usage"] = pricing_tracker.get_project_usage(project_name)
        scan_results["successful"] = True
        
        scan_duration = time.time() - scan_start_time
        files_count = len(relevant_files)
        vuln_count = len(all_vulns)
        
        # Save scan results to file
        results_file = project_output_dir / "scan_results.json"
        with open(results_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        console.print(f"\n[bold green]Scan Complete for {project_name}![/bold green]")
        console.print(f"Files scanned: [bold]{files_count}[/bold]")
        console.print(f"Vulnerabilities found: [bold]{vuln_count}[/bold]")
        console.print(f"Scan duration: [bold]{scan_duration:.2f}s[/bold]")
        console.print(f"Results saved to: [bold]{project_output_dir}[/bold]")
        
        token_usage = pricing_tracker.get_project_usage(project_name)
        console.print(f"Token usage: [bold]{token_usage['input_tokens']}[/bold] input, [bold]{token_usage['output_tokens']}[/bold] output")
        console.print(f"Estimated cost: [bold]${token_usage['cost']:.4f}[/bold]")
        
        logger.info(f"Scan completed for {project_name}. Found {vuln_count} vulnerabilities in {files_count} files.")
        logger.info(f"Token usage: {token_usage['input_tokens']} input, {token_usage['output_tokens']} output. Cost: ${token_usage['cost']:.4f}")
        
    except Exception as e:
        logger.exception(f"Error scanning project {project_name}")
        console.print(f"[bold red]Error scanning project {project_name}:[/bold red] {str(e)}")
        scan_results["error"] = str(e)
    
    return scan_results

def orchestrate_scans(input_dir: Path, output_dir: Path, config: Config) -> Dict[str, Any]:
    """
    Orchestrate scanning of all projects in the input directory.
    
    Args:
        input_dir: Path to the input directory
        output_dir: Path to the output directory
        config: Configuration for the scan
        
    Returns:
        Dict[str, Any]: Summary of all scans
    """
    console.print(f"[bold]Looking for projects in:[/bold] {input_dir}")
    
    # Get all subdirectories in the input directory
    projects = []
    for item in input_dir.iterdir():
        if item.is_dir():
            projects.append(item)
    
    if not projects:
        console.print("[bold red]No project directories found in input folder[/bold red]")
        return {"error": "No project directories found"}
    
    console.print(f"[bold green]Found {len(projects)} projects to scan[/bold green]")
    for project in projects:
        console.print(f"  - {project.name}")
    
    # Set up global pricing tracker
    pricing_tracker = PricingTracker()
    
    # Process each project
    results = {}
    for project_dir in projects:
        project_name = project_dir.name
        results[project_name] = scan_single_project(project_dir, output_dir, config, pricing_tracker)
        update_global_pricing(pricing_tracker.get_project_usage(project_name))
    
    # Create summary report
    summary = {
        "scan_time": datetime.now().isoformat(),
        "projects_scanned": len(projects),
        "successful_scans": sum(1 for r in results.values() if r.get("successful", False)),
        "total_vulnerabilities": sum(len(r.get("vulnerabilities", [])) for r in results.values()),
        "token_usage": pricing_tracker.get_total_usage(),
        "project_results": results
    }
    
    summary_file = output_dir / "scan_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    console.print("\n[bold green]All scans completed![/bold green]")
    console.print(f"Projects scanned: [bold]{summary['projects_scanned']}[/bold]")
    console.print(f"Successful scans: [bold]{summary['successful_scans']}/{summary['projects_scanned']}[/bold]")
    console.print(f"Total vulnerabilities found: [bold]{summary['total_vulnerabilities']}[/bold]")
    
    token_usage = summary["token_usage"]
    console.print(f"Total token usage: [bold]{token_usage['input_tokens']}[/bold] input, [bold]{token_usage['output_tokens']}[/bold] output")
    console.print(f"Total estimated cost: [bold]${token_usage['cost']:.4f}[/bold]")
    
    return summary

def run_orchestrator(api_key: str):
    """
    Run the project orchestrator with the given API key.
    
    Args:
        api_key: OpenAI API key
    """
    # Set up environment variables for configuration
    os.environ["OPENAI_API_KEY"] = api_key
    os.environ["OPENAI_MODEL"] = "gpt-4o"  # Always use GPT-4o
    
    # Get input and output directories
    base_dir = Path("/project")
    input_dir = base_dir / "input"
    output_dir = base_dir / "output"
    
    if not input_dir.exists() or not input_dir.is_dir():
        console.print(f"[bold red]Input directory not found: {input_dir}[/bold red]")
        return
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(exist_ok=True, parents=True)
    
    # Set up configuration
    try:
        config = setup_config()
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] Failed to setup configuration: {str(e)}")
        return
    
    # Run the orchestrator
    try:
        orchestrate_scans(input_dir, output_dir, config)
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {str(e)}")
