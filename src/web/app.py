"""
Web interface for AI_SAST (modified to support the new project structure)
"""

import os
import json
import time
import threading
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.config import Config
from project_orchestrator import run_orchestrator
from scanner.pricing_tracker import get_global_pricing

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SESSION_TYPE'] = 'filesystem'

# Base project directory structure
BASE_DIR = Path("/project")
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"

# API key storage (in-memory only, not persistent)
API_KEY = None
SCANNING_IN_PROGRESS = False
CURRENT_SCAN_PROGRESS = 0
SCAN_STATUS = "idle"
SCAN_OPTIONS = {
    "enable_codeql": True,
    "codeql_language": "javascript"
}

def sanitize_folder_name(name):
    """Sanitize folder name to ensure consistency between generation and retrieval"""
    return re.sub(r'[^\w\-]', '_', name)

def get_project_folders():
    """Get a list of all project folders in the input directory"""
    if not INPUT_DIR.exists():
        return []
    
    projects = []
    for item in INPUT_DIR.iterdir():
        if item.is_dir():
            projects.append({
                'name': item.name,
                'path': str(item),
                'file_count': sum(1 for _ in item.glob('**/*') if _.is_file())
            })
    
    return projects

def get_analyzed_folders():
    """Get list of all analyzed folders in the output directory"""
    if not OUTPUT_DIR.exists():
        return []
    
    folders = []
    for folder in OUTPUT_DIR.iterdir():
        if folder.is_dir():
            try:
                # Look for scan results
                results_file = folder / "scan_results.json"
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        results = json.load(f)
                    
                    vuln_count = len(results.get("vulnerabilities", []))
                    timestamp = results.get("scan_time", "")
                    
                    folders.append({
                        'id': folder.name,
                        'name': folder.name,
                        'timestamp': timestamp,
                        'date': timestamp.split('T')[0] if 'T' in timestamp else timestamp,
                        'vulnerability_count': vuln_count
                    })
            except Exception as e:
                print(f"Error reading results for {folder.name}: {str(e)}")
    
    # Sort by timestamp (newest first)
    folders.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return folders

def get_folder_details(folder_id):
    """Get details for a specific analysis folder"""
    folder_path = OUTPUT_DIR / folder_id
    
    if not folder_path.exists() or not folder_path.is_dir():
        return None
    
    try:
        results_file = folder_path / "scan_results.json"
        if not results_file.exists():
            return None
            
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        vulnerabilities = results.get("vulnerabilities", [])
        
        # Calculate severity counts
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate vulnerability types
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        return {
            'id': folder_id,
            'name': folder_id,
            'vulnerabilities': vulnerabilities,
            'severity_counts': severity_counts,
            'vulnerability_types': vuln_types,
            'total_vulnerabilities': len(vulnerabilities),
            'token_usage': results.get("token_usage", {
                "input_tokens": 0,
                "output_tokens": 0,
                "cost": 0.0
            })
        }
    except Exception as e:
        print(f"Error getting details for {folder_id}: {str(e)}")
        return None

def update_global_pricing_from_file():
    """Update global pricing from the pricing data file"""
    try:
        pricing_file = Path("/project/pricing_data.json")
        if pricing_file.exists():
            with open(pricing_file, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "cost": 0.0
    }

def run_orchestrator_thread(api_key):
    """
    Run the orchestrator in a separate thread.
    
    Args:
        api_key: OpenAI API key
    """
    global SCANNING_IN_PROGRESS, CURRENT_SCAN_PROGRESS, SCAN_STATUS
    
    SCANNING_IN_PROGRESS = True
    SCAN_STATUS = "running"
    CURRENT_SCAN_PROGRESS = 5
    
    try:
        # Apply scan options to environment variables
        os.environ["ENABLE_CODEQL"] = str(SCAN_OPTIONS["enable_codeql"]).lower()
        os.environ["CODEQL_LANGUAGE"] = SCAN_OPTIONS["codeql_language"]
        
        run_orchestrator(api_key)
        SCAN_STATUS = "completed"
    except Exception as e:
        print(f"Error in orchestrator: {str(e)}")
        SCAN_STATUS = "failed"
    finally:
        SCANNING_IN_PROGRESS = False
        CURRENT_SCAN_PROGRESS = 100

@app.context_processor
def inject_pricing_data():
    """Inject pricing data into all templates"""
    pricing_data = update_global_pricing_from_file()
    return {
        'pricing_data': pricing_data,
        'scanning_in_progress': SCANNING_IN_PROGRESS,
        'scan_status': SCAN_STATUS
    }

@app.route('/')
def index():
    """Home page - redirect to setup page if API key is not set"""
    if not API_KEY:
        return redirect(url_for('setup'))
    
    folders = get_analyzed_folders()
    return render_template('index.html', folders=folders)

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """API key setup page"""
    global API_KEY
    
    if request.method == 'POST':
        api_key = request.form.get('openai_key')
        
        if not api_key or not api_key.startswith('sk-'):
            flash('Please provide a valid OpenAI API key', 'error')
            return redirect(url_for('setup'))
        
        API_KEY = api_key
        os.environ["OPENAI_API_KEY"] = api_key
        
        flash('API key saved successfully', 'success')
        return redirect(url_for('index'))
    
    return render_template('setup.html')

@app.route('/projects')
def projects():
    """Projects page - list all project folders"""
    if not API_KEY:
        return redirect(url_for('setup'))
    
    project_folders = get_project_folders()
    return render_template('projects.html', projects=project_folders)

@app.route('/analysis/<folder_id>')
def analysis_details(folder_id):
    """Show analysis results for a specific folder"""
    if not API_KEY:
        return redirect(url_for('setup'))
    
    details = get_folder_details(folder_id)
    if not details:
        abort(404)
    
    return render_template('analysis.html', details=details)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan all projects"""
    global SCANNING_IN_PROGRESS, SCAN_OPTIONS
    
    if not API_KEY:
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        if SCANNING_IN_PROGRESS:
            flash('A scan is already in progress', 'error')
            return redirect(url_for('scan_status'))
        
        # Update scan options from form
        SCAN_OPTIONS["enable_codeql"] = 'enable_codeql' in request.form
        SCAN_OPTIONS["codeql_language"] = request.form.get('codeql_language', 'javascript')
        
        # Start scan in a separate thread
        thread = threading.Thread(target=run_orchestrator_thread, args=(API_KEY,))
        thread.daemon = True
        thread.start()
        
        flash('Scan started for all projects', 'success')
        return redirect(url_for('scan_status'))
    
    project_folders = get_project_folders()
    return render_template('scan.html', projects=project_folders)

@app.route('/scan/status')
def scan_status():
    """Show the status of the current scan"""
    if not API_KEY:
        return redirect(url_for('setup'))
    
    return render_template('scan_status.html', 
                          scanning=SCANNING_IN_PROGRESS, 
                          progress=CURRENT_SCAN_PROGRESS,
                          status=SCAN_STATUS)

@app.route('/api/scan/status')
def api_scan_status():
    """API endpoint to get scan status"""
    pricing_data = update_global_pricing_from_file()
    
    return jsonify({
        'scanning': SCANNING_IN_PROGRESS,
        'progress': CURRENT_SCAN_PROGRESS,
        'status': SCAN_STATUS,
        'pricing': pricing_data
    })

@app.route('/api/pricing')
def api_pricing():
    """API endpoint to get pricing data"""
    return jsonify(update_global_pricing_from_file())

if __name__ == '__main__':
    # Create base directory structure if it doesn't exist
    INPUT_DIR.mkdir(exist_ok=True, parents=True)
    OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
    
    app.run(debug=True, host='0.0.0.0')
