"""
CodeQL scanner module for AI_SAST.

Provides functionality to run CodeQL analysis on code.
"""

import os
import subprocess
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger("ai_sast")

def setup_codeql_environment() -> bool:
    """Verify CodeQL CLI is available and set up environment variables."""
    try:
        result = subprocess.run(["codeql", "--version"], 
                              capture_output=True, text=True, check=True)
        logger.info(f"CodeQL version: {result.stdout.strip()}")
        return True
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.error(f"CodeQL not available: {str(e)}")
        return False

def create_codeql_database(src_dir: Path, db_path: Path, language: str = "javascript") -> bool:
    """Create a CodeQL database for the source code.
    
    Args:
        src_dir: Source directory
        db_path: Output path for CodeQL database
        language: Programming language to analyze
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Ensure the database directory exists
        db_path.mkdir(parents=True, exist_ok=True)
        
        command = [
            "codeql", "database", "create", 
            f"--language={language}",
            "--source-root", str(src_dir),
            str(db_path)
        ]
        
        logger.info(f"Creating CodeQL database: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(f"CodeQL database created at {db_path}")
        return True
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to create CodeQL database: {str(e)}")
        logger.debug(f"Output: {e.stdout if hasattr(e, 'stdout') else ''}")
        logger.debug(f"Error: {e.stderr if hasattr(e, 'stderr') else ''}")
        return False

def run_codeql_queries(db_path: Path, output_dir: Path, language: str = "javascript") -> List[Dict[str, Any]]:
    """Run CodeQL security queries against the database.
    
    Args:
        db_path: Path to CodeQL database
        output_dir: Directory to store results
        language: Programming language to analyze
        
    Returns:
        List[Dict[str, Any]]: Processed vulnerability findings
    """
    try:
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up query paths based on language
        if language.lower() == "javascript":
            query_suites = ["/opt/codeql-repo/javascript/ql/src/Security/CWE"]
        else:
            # Default to a general security query suite
            query_suites = [f"/opt/codeql-repo/{language}/ql/src/Security"]
        
        results_path = output_dir / "codeql-results.sarif"
        
        command = [
            "codeql", "database", "analyze", 
            "--format=sarif-latest",
            "--output", str(results_path),
            str(db_path)
        ]
        
        # Add query suites to command
        command.extend(query_suites)
        
        logger.info(f"Running CodeQL analysis: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Process SARIF results into our vulnerability format
        return process_sarif_results(results_path)
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to run CodeQL queries: {str(e)}")
        logger.debug(f"Output: {e.stdout if hasattr(e, 'stdout') else ''}")
        logger.debug(f"Error: {e.stderr if hasattr(e, 'stderr') else ''}")
        return []

def process_sarif_results(sarif_path: Path) -> List[Dict[str, Any]]:
    """Process SARIF results into our vulnerability format.
    
    Args:
        sarif_path: Path to SARIF results file
        
    Returns:
        List[Dict[str, Any]]: Processed vulnerability findings
    """
    vulnerabilities = []
    
    try:
        if not sarif_path.exists():
            logger.warning(f"SARIF file not found: {sarif_path}")
            return []
            
        with open(sarif_path, 'r') as f:
            sarif_data = json.load(f)
        
        # Extract results from SARIF format
        for run in sarif_data.get('runs', []):
            tool = run.get('tool', {}).get('driver', {})
            rules = {rule.get('id'): rule for rule in tool.get('rules', [])}
            
            for result in run.get('results', []):
                rule_id = result.get('ruleId')
                rule = rules.get(rule_id, {})
                
                # Get the first location
                locations = result.get('locations', [])
                if not locations:
                    continue
                
                location = locations[0]
                physical_location = location.get('physicalLocation', {})
                artifact_location = physical_location.get('artifactLocation', {})
                region = physical_location.get('region', {})
                
                # Extract the file path
                file_path = artifact_location.get('uri', '')
                if file_path.startswith('file:'):
                    file_path = file_path[5:]
                
                # Create vulnerability entry
                vuln = {
                    "vulnerability_type": rule.get('name', rule_id or 'Unknown'),
                    "description": result.get('message', {}).get('text', ''),
                    "location": {
                        "file": file_path,
                        "line": region.get('startLine', 0),
                        "column": region.get('startColumn', 0)
                    },
                    "severity": map_codeql_severity(result.get('level', '')),
                    "recommendation": extract_recommendation(rule),
                    "source": "CodeQL"  # Add a source field to distinguish from AI findings
                }
                
                vulnerabilities.append(vuln)
                
        return vulnerabilities
    except Exception as e:
        logger.error(f"Error processing SARIF results: {str(e)}")
        return []

def map_codeql_severity(level: str) -> str:
    """Map CodeQL severity levels to our severity format.
    
    Args:
        level: CodeQL severity level
        
    Returns:
        str: Mapped severity
    """
    severity_map = {
        'error': 'critical',
        'warning': 'high',
        'note': 'medium',
        'none': 'low'
    }
    
    return severity_map.get(level.lower(), 'medium')

def extract_recommendation(rule: Dict) -> str:
    """Extract recommendation from rule information.
    
    Args:
        rule: CodeQL rule information
        
    Returns:
        str: Recommendation text
    """
    # Try to get recommendation from different possible locations in the rule data
    help_text = rule.get('help', {}).get('text', '')
    help_markdown = rule.get('help', {}).get('markdown', '')
    
    if help_markdown:
        return help_markdown
    elif help_text:
        return help_text
    else:
        return f"Fix the {rule.get('name', 'issue')} by following secure coding practices."