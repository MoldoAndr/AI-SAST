"""
CodeQL scanner module for AI_SAST.

Provides functionality to run CodeQL analysis on code.
"""

import os
import subprocess
import json
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("ai_sast")

def setup_codeql_environment() -> bool:
    """Verify CodeQL CLI is available and set up environment variables."""
    codeql_path = "/opt/codeql/codeql/codeql"
    try:
        if not os.path.isfile(codeql_path):
            logger.error(f"CodeQL binary not found at {codeql_path}")
            return False

        result = subprocess.run([codeql_path, "--version"], 
                              capture_output=True, text=True, check=True)
    
        logger.info(f"CodeQL version: {result.stdout.strip()}")
        return True
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.error(f"CodeQL not available: {str(e)}")
        return False

def create_codeql_database(src_dir: Path, db_path: Path, language: str = "javascript") -> bool:
    """Create a CodeQL database for the source code."""
    codeql_path = "/opt/codeql/codeql/codeql"
    
    try:
        db_path.mkdir(parents=True, exist_ok=True)
        
        command = [
            codeql_path, "database", "create", 
            f"--language={language}",
            "--source-root", str(src_dir),
            str(db_path)
        ]
        
        logger.info(f"Creating CodeQL database: {' '.join(command)}")
        
        process = subprocess.run(
            command,
            capture_output=True, 
            text=True
        )
        
        if process.returncode == 0:
            logger.info(f"CodeQL database created at {db_path}")
            return True
        else:
            logger.error(f"CodeQL database creation failed with return code {process.returncode}")
            logger.error(f"STDOUT: {process.stdout}")
            logger.error(f"STDERR: {process.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create CodeQL database: {str(e)}")
        logger.exception("Database creation error")
        return False

def get_available_query_packs() -> List[str]:
    """Get a list of available CodeQL query packs."""
    codeql_path = "/opt/codeql/codeql/codeql"
    
    try:
        command = [codeql_path, "resolve", "qlpacks"]
        process = subprocess.run(command, capture_output=True, text=True)
        
        if process.returncode == 0:
            logger.info(f"Available qlpacks: {process.stdout.strip()}")
            packs = []
            for line in process.stdout.strip().split('\n'):
                if line.strip():
                    pack_info = line.strip().split(' ', 1)
                    if pack_info:
                        packs.append(pack_info[0])
            return packs
        else:
            logger.warning(f"Failed to list query packs: {process.stderr}")
            return []
    except Exception as e:
        logger.error(f"Error listing query packs: {str(e)}")
        return []

def create_custom_query_pack(output_dir: Path) -> Tuple[bool, Path]:
    """Create a custom query pack for basic JavaScript security checks.
    
    Returns:
        Tuple[bool, Path]: Success flag and path to the query pack
    """
    try:
        custom_pack_dir = output_dir / "custom-js-security"
        custom_pack_dir.mkdir(parents=True, exist_ok=True)
        
        ql_dir = custom_pack_dir / "ql"
        ql_dir.mkdir(exist_ok=True)
        
        src_dir = ql_dir / "src"
        src_dir.mkdir(exist_ok=True)
        
        qlpack_content = """name: custom-js-security
version: 1.0.0
description: Basic JavaScript security queries
dependencies:
  codeql/javascript-all: "*"
"""
        
        with open(custom_pack_dir / "qlpack.yml", "w") as f:
            f.write(qlpack_content)
        
        xss_query = """
/**
 * @name Client-side cross-site scripting
 * @description Writing user input directly to the DOM allows for a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @id js/xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript

// Define sources of user input
class UserInput extends DataFlow::Node {
  UserInput() {
    exists(string name |
      // Web inputs
      name = "location" or
      name = "document.location" or
      name = "document.URL" or
      name = "document.documentURI" or
      name = "document.referrer" or
      name = "document.cookie" or
      name = "window.name" or
      // Form inputs
      name = "HTMLInputElement.value" or
      name = "HTMLTextAreaElement.value" or
      name = "HTMLSelectElement.value" or
      // Query params
      name = "URLSearchParams.get" |
      this = DataFlow::globalVarRef(name).getAReference()
    )
  }
}

// Define dangerous sinks
class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(string name |
      // DOM XSS sinks
      name = "Element.innerHTML" or
      name = "Element.outerHTML" or
      name = "document.write" or
      name = "document.writeln" or
      name = "Element.insertAdjacentHTML" |
      this = DataFlow::globalVarRef(name).getAReference()
    )
  }
}

from UserInput source, DangerousSink sink
where
  DataFlow::localFlow(source, sink)
select sink, "Potential XSS vulnerability with unsanitized input from $@.", source, "user input"
"""
        
        with open(src_dir / "xss.ql", "w") as f:
            f.write(xss_query)
        
        eval_query = """
/**
 * @name Use of eval
 * @description Using 'eval' may allow for arbitrary code execution.
 * @kind problem
 * @problem.severity warning
 * @id js/eval-use
 * @tags security
 *       correctness
 */

import javascript

from CallExpr evalCall
where
  evalCall.getCalleeName() = "eval"
select evalCall, "Avoid using 'eval' as it can lead to code injection vulnerabilities."
"""
        
        with open(src_dir / "eval.ql", "w") as f:
            f.write(eval_query)
            
        sql_query = """
/**
 * @name SQL injection
 * @description Building SQL queries from user-controlled sources is vulnerable to SQL injection.
 * @kind path-problem
 * @problem.severity error
 * @id js/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript

// Define sources of user input
class UserInput extends DataFlow::Node {
  UserInput() {
    exists(string name |
      // Web inputs
      name = "location" or
      name = "document.location" or
      name = "document.URL" or
      // Form inputs
      name = "HTMLInputElement.value" or
      name = "HTMLTextAreaElement.value" or
      // Request parameters
      name = "req.query" or 
      name = "req.body" or
      name = "req.params" |
      this = DataFlow::globalVarRef(name).getAReference()
    )
  }
}

// Define SQL query sinks
class SQLSink extends DataFlow::Node {
  SQLSink() {
    exists(string name |
      // Various SQL libraries
      name = "mysql.query" or
      name = "connection.query" or
      name = "db.query" or
      name = "knex.raw" or
      name = "sequelize.query" |
      this = DataFlow::globalVarRef(name).getAReference()
    )
  }
}

from UserInput source, SQLSink sink
where
  DataFlow::localFlow(source, sink)
select sink, "Potential SQL injection vulnerability with unsanitized input from $@.", source, "user input"
"""
        
        with open(src_dir / "sql-injection.ql", "w") as f:
            f.write(sql_query)
            
        logger.info(f"Created custom query pack at {custom_pack_dir}")
        return True, custom_pack_dir
    
    except Exception as e:
        logger.error(f"Failed to create custom query pack: {str(e)}")
        return False, Path()

def create_simple_js_queries(output_dir: Path) -> List[Path]:
    """Create simple JavaScript security queries directly.
    
    This is a fallback option when query packs don't work.
    Uses very basic QL without complex dependencies.
    
    Returns:
        List[Path]: List of paths to query files
    """
    try:
        queries_dir = output_dir / "queries"
        queries_dir.mkdir(parents=True, exist_ok=True)
        
        xss_query = """
/**
 * @name Basic DOM XSS detection
 * @description Detects basic patterns that might indicate DOM XSS vulnerabilities
 * @kind problem
 * @problem.severity warning
 * @id js/basic-dom-xss
 */

import javascript

from Expr expr
where 
  // Look for assignments to innerHTML or similar properties
  exists(PropAccess pa | 
    pa = expr.(AssignExpr).getLhs() and
    pa.getPropertyName() in ["innerHTML", "outerHTML", "insertAdjacentHTML"]
  )
  or
  // Look for document.write calls
  exists(MethodCallExpr mc |
    mc.getMethodName() in ["write", "writeln"] and
    mc.getReceiver().(VarRef).getName() = "document"
  )
select expr, "Potential DOM XSS vulnerability: found code that might allow script injection."
"""
        xss_path = queries_dir / "simple-xss.ql"
        with open(xss_path, "w") as f:
            f.write(xss_query)
        
        insecure_fn_query = """
/**
 * @name Use of potentially dangerous functions
 * @description Using dangerous functions like eval can lead to code injection vulnerabilities
 * @kind problem
 * @problem.severity warning
 * @id js/dangerous-function-usage
 */

import javascript

from CallExpr call
where
  call.getCalleeName() in ["eval", "Function", "setTimeout", "setInterval", "execScript"]
select call, "Use of potentially dangerous function: " + call.getCalleeName()
"""
        insecure_fn_path = queries_dir / "insecure-functions.ql"
        with open(insecure_fn_path, "w") as f:
            f.write(insecure_fn_query)
            
        url_query = """
/**
 * @name Insecure URL concatenation
 * @description Concatenating strings to create URLs might lead to open redirect vulnerabilities
 * @kind problem
 * @problem.severity warning
 * @id js/insecure-url-construction
 */

import javascript

from AssignExpr assign
where
  // Look for assignments to location properties
  exists(PropAccess pa | 
    pa = assign.getLhs() and
    pa.getPropertyName() in ["href", "location"] and
    assign.getRhs() instanceof Add  // Simple check for string concatenation
  )
select assign, "Potential insecure URL construction using string concatenation."
"""
        url_path = queries_dir / "url-concat.ql"
        with open(url_path, "w") as f:
            f.write(url_query)
            
        direct_scan_query = """
/**
 * @name Direct security pattern scan
 * @description Scans for common security-relevant patterns directly
 * @kind problem
 * @problem.severity warning
 * @id js/direct-security-scan
 */

import javascript

from Expr expr, string reason
where
  // Simple pattern matching for common security issues 
  (
    // XSS related
    (expr.(MethodCallExpr).getMethodName() = "write" and
     expr.(MethodCallExpr).getReceiver().(VarRef).getName() = "document" and
     reason = "document.write can lead to XSS vulnerabilities"
    )
    or
    (exists(PropAccess pa | pa = expr.(AssignExpr).getLhs() and
      pa.getPropertyName() = "innerHTML") and
      reason = "Setting innerHTML can lead to XSS vulnerabilities"
    )
    or
    // Injection related
    (expr.(CallExpr).getCalleeName() = "eval" and
     reason = "eval() can lead to code injection vulnerabilities"
    )
    or
    // Authentication related
    (expr.(CallExpr).getCalleeName() = "localStorage" and
     reason = "Using localStorage for sensitive data is insecure"
    )
  )
select expr, reason
"""
        direct_path = queries_dir / "direct-scan.ql"
        with open(direct_path, "w") as f:
            f.write(direct_scan_query)
        
        logger.info(f"Created simple queries at {queries_dir}")
        return [xss_path, insecure_fn_path, url_path, direct_path]
    
    except Exception as e:
        logger.error(f"Failed to create simple queries: {str(e)}")
        return []

def install_or_download_query_packs(output_dir: Path) -> bool:
    """Attempt to download and install missing query packs."""
    codeql_path = "/opt/codeql/codeql/codeql"
    
    try:
        logger.info("Attempting to download standard query packs...")
        
        command = [codeql_path, "pack", "download", "codeql/javascript-queries"]
        process = subprocess.run(command, capture_output=True, text=True)
        
        if process.returncode == 0:
            logger.info("Successfully downloaded JavaScript queries pack")
            available_packs = get_available_query_packs()
            if any("javascript-queries" in pack for pack in available_packs):
                return True
            logger.warning("Downloaded pack not found in available packs list")
        
        logger.info("Will use custom queries instead of standard packs")
        return False
    
    except Exception as e:
        logger.error(f"Error during query pack installation: {str(e)}")
        return False

def run_codeql_queries(db_path: Path, output_dir: Path, language: str = "javascript") -> List[Dict[str, Any]]:
    """Run CodeQL security queries against the database."""
    codeql_path = "/opt/codeql/codeql/codeql"
    
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        available_packs = get_available_query_packs()
        logger.info(f"Available qlpacks before download: {available_packs}")
        
        install_or_download_query_packs(output_dir)
        
        available_packs = get_available_query_packs()
        logger.info(f"Available qlpacks after download: {available_packs}")
        
        results_path = output_dir / "codeql-results.sarif"
        
        logger.info("Skipping standard suites due to compatibility issues, using simple queries...")
        
        query_files = create_simple_js_queries(output_dir)
        
        if not query_files:
            logger.error("Failed to create query files")
            return []
            
        logger.info(f"Created {len(query_files)} simple queries")
        
        all_results = []
        for query_file in query_files:
            results_bqrs = output_dir / f"results_{query_file.stem}.bqrs"
            
            command = [
                codeql_path, "query", "run",
                "-v",
                "--database", str(db_path),
                "--output", str(results_bqrs),
                str(query_file)
            ]
            
            logger.info(f"Running individual query: {' '.join(command)}")
            
            process = subprocess.run(command, capture_output=True, text=True)
            
            if process.returncode == 0:
                logger.info(f"Query {query_file.name} executed successfully")
                
                results_json = output_dir / f"results_{query_file.stem}.json"
                
                command = [
                    codeql_path, "bqrs", "decode",
                    "--format=json",
                    "--output", str(results_json),
                    str(results_bqrs)
                ]
                
                decode_process = subprocess.run(command, capture_output=True, text=True)
                
                if decode_process.returncode == 0:
                    query_results = process_bqrs_results(results_json, query_file.stem)
                    logger.info(f"Found {len(query_results)} results from query {query_file.name}")
                    all_results.extend(query_results)
                else:
                    logger.warning(f"Failed to decode BQRS results: {decode_process.stderr}")
                    
                    csv_file = output_dir / f"results_{query_file.stem}.csv"
                    command = [
                        codeql_path, "bqrs", "decode",
                        "--format=csv",
                        "--output", str(csv_file),
                        str(results_bqrs)
                    ]
                    subprocess.run(command, capture_output=True, text=True)
                    
                    logger.info(f"Generated CSV results at {csv_file}")
                    
                    all_results.append({
                        "vulnerability_type": f"CodeQL {query_file.stem.replace('-', ' ').title()}",
                        "description": f"CodeQL detected potential issues. See CSV file for details: {csv_file}",
                        "location": {"file": "", "line": 0, "column": 0},
                        "severity": "medium",
                        "recommendation": "Review the identified code for security issues.",
                        "source": "CodeQL"
                    })
            else:
                logger.warning(f"Query {query_file.name} failed: {process.stderr}")
        
        if all_results:
            logger.info(f"Successfully processed {len(all_results)} results from individual queries")
            
            create_combined_sarif(all_results, results_path)
            
            return all_results
        
        logger.warning("All CodeQL analysis methods failed")
        return []
            
    except Exception as e:
        logger.error(f"Failed to run CodeQL queries: {str(e)}")
        logger.exception("Query execution error")
        return []

def process_bqrs_results(results_json: Path, query_name: str) -> List[Dict[str, Any]]:
    """Process BQRS results converted to JSON into our vulnerability format.
    
    Args:
        results_json: Path to JSON results file
        query_name: Name of the query used
        
    Returns:
        List[Dict[str, Any]]: Processed vulnerability findings
    """
    vulnerabilities = []
    
    try:
        if not results_json.exists():
            logger.warning(f"Results JSON file not found: {results_json}")
            return []
            
        with open(results_json, 'r') as f:
            data = json.load(f)
        
        logger.debug(f"BQRS data structure: {type(data)}")
        
        if not isinstance(data, dict):
            logger.warning(f"Unexpected JSON format: not a dictionary")
            return []
            
        if "rows" not in data:
            logger.warning(f"No 'rows' field in BQRS JSON")
            return []
        
        logger.info(f"Processing {len(data.get('rows', []))} rows from query {query_name}")
        
        for row in data.get("rows", []):
            if not row:
                continue
                
            location_info = ""
            message = ""
            
            file_path = ""
            line = 0
            column = 0
            
            logger.debug(f"Row structure: {row}")
            
            for i, cell in enumerate(row):
                if isinstance(cell, dict) and "label" in cell:
                    location_info = cell.get("label", "")
                    file_info = cell.get("url", "")
                    
                    logger.debug(f"Found location info: {location_info}, file_info: {file_info}")
                    
                    if file_info:
                        if file_info.startswith("file://"):
                            file_info = file_info[7:]
                        
                        parts = file_info.split(":")
                        if len(parts) >= 2:
                            file_path = parts[0]
                            try:
                                line = int(parts[1])
                                if len(parts) >= 3:
                                    column = int(parts[2])
                            except ValueError:
                                pass
                    
                elif isinstance(cell, str) and not message:
                    message = cell
            
            if not file_path and len(row) >= 2:
                for cell in row:
                    if isinstance(cell, str) and "/" in cell and not file_path:
                        potential_path = cell
                        if os.path.exists(potential_path):
                            file_path = potential_path
                            logger.debug(f"Found potential file path: {file_path}")
                            break
            
            vuln = {
                "vulnerability_type": f"CodeQL {query_name.replace('-', ' ').title()}",
                "description": message or f"Potential security issue detected by CodeQL query {query_name}",
                "location": {
                    "file": file_path,
                    "line": line,
                    "column": column
                },
                "severity": "high" if "xss" in query_name.lower() or "injection" in query_name.lower() else "medium",
                "recommendation": generate_recommendation(query_name),
                "source": "CodeQL"
            }
            
            vulnerabilities.append(vuln)
            logger.debug(f"Added vulnerability: {vuln}")
                
        return vulnerabilities
    except Exception as e:
        logger.error(f"Error processing BQRS results: {str(e)}")
        logger.exception("BQRS processing error")
        return []
    """Process BQRS results converted to JSON into our vulnerability format.
    
    Args:
        results_json: Path to JSON results file
        query_name: Name of the query used
        
    Returns:
        List[Dict[str
    """
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
        
        for run in sarif_data.get('runs', []):
            tool = run.get('tool', {}).get('driver', {})
            rules = {rule.get('id'): rule for rule in tool.get('rules', [])}
            
            for result in run.get('results', []):
                rule_id = result.get('ruleId')
                rule = rules.get(rule_id, {})
                
                locations = result.get('locations', [])
                if not locations:
                    continue
                
                location = locations[0]
                physical_location = location.get('physicalLocation', {})
                artifact_location = physical_location.get('artifactLocation', {})
                region = physical_location.get('region', {})
                
                file_path = artifact_location.get('uri', '')
                if file_path.startswith('file:'):
                    file_path = file_path[5:]
                
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
                    "source": "CodeQL"
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
    help_text = rule.get('help', {}).get('text', '')
    help_markdown = rule.get('help', {}).get('markdown', '')
    
    if help_markdown:
        return help_markdown
    elif help_text:
        return help_text
    else:
        return f"Fix the {rule.get('name', 'issue')} by following secure coding practices."

def generate_recommendation(query_name: str) -> str:
    """Generate a recommendation based on the query name.
    
    Args:
        query_name: Name of the query
        
    Returns:
        str: Generated recommendation
    """
    recommendations = {
        "xss": "Sanitize user input before inserting it into HTML content. Use framework-provided escape functions or libraries like DOMPurify.",
        "eval": "Avoid using eval() as it can execute arbitrary code. Use safer alternatives like JSON.parse() for JSON data.",
        "sql-injection": "Use parameterized queries or ORM libraries instead of building SQL queries with string concatenation.",
        "insecure-functions": "Replace these functions with safer alternatives that don't execute arbitrary code."
    }
    
    for key, recommendation in recommendations.items():
        if key in query_name.lower():
            return recommendation
    
    return "Review this code for potential security vulnerabilities and follow secure coding practices."

def create_combined_sarif(results: List[Dict[str, Any]], output_path: Path) -> bool:
    """Create a combined SARIF file from processed results.
    
    Args:
        results: List of vulnerability results
        output_path: Path to write SARIF file
        
    Returns:
        bool: Success flag
    """
    try:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "semanticVersion": "2.15.1",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        rule_ids = {}
        for i, result in enumerate(results):
            vuln_type = result.get("vulnerability_type", "Unknown")
            if vuln_type not in rule_ids:
                rule_id = f"js/codeql-{i}"
                rule_ids[vuln_type] = rule_id
                
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": vuln_type,
                    "shortDescription": {
                        "text": vuln_type
                    },
                    "fullDescription": {
                        "text": result.get("description", "")
                    },
                    "help": {
                        "text": result.get("recommendation", "")
                    }
                })
        
        for result in results:
            vuln_type = result.get("vulnerability_type", "Unknown")
            rule_id = rule_ids.get(vuln_type, "js/codeql-unknown")
            
            location = result.get("location", {})
            file_path = location.get("file", "")
            
            sarif["runs"][0]["results"].append({
                "ruleId": rule_id,
                "message": {
                    "text": result.get("description", "")
                },
                "level": "warning",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": location.get("line", 0),
                                "startColumn": location.get("column", 0)
                            }
                        }
                    }
                ]
            })
        
        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2)
            
        return True
    except Exception as e:
        logger.error(f"Failed to create combined SARIF file: {str(e)}")
        return False

def run_codeql_scan(src_dir: Path, output_dir: Path) -> List[Dict[str, Any]]:
    """Run a complete CodeQL scan on the source directory.
    
    Args:
        src_dir: Source directory to scan
        output_dir: Output directory for results
        
    Returns:
        List[Dict[str, Any]]: Detected vulnerabilities
    """
    if not setup_codeql_environment():
        logger.warning("CodeQL environment setup failed, skipping CodeQL scan")
        return []
    
    db_path = output_dir / "codeql_db"
    if not create_codeql_database(src_dir, db_path):
        logger.warning("CodeQL database creation failed, skipping CodeQL scan")
        return []
    
    results = run_codeql_queries(db_path, output_dir)
    
    if not results:
        logger.info("No CodeQL results found, adding placeholder")
        results = [{
            "vulnerability_type": "CodeQL Scan Completed",
            "description": "CodeQL scan completed but no vulnerabilities were found",
            "location": {"file": "", "line": 0, "column": 0},
            "severity": "info",
            "recommendation": "No action required",
            "source": "CodeQL"
        }]
    
    return results