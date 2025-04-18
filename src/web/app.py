"""
Web interface for AI_SAST (modificat pentru a suporta scanarea directoarelor montate)
"""

import os
import json
import time
import threading
import subprocess
import re
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from werkzeug.utils import secure_filename

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.config import Config, setup_config

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Directoriul montat pentru scanare
MOUNTED_SRC_DIR = os.getenv("SRC_DIR", "/project")

JOBS = {}

ENTRYPOINT_API_KEY = os.getenv("OPENAI_API_KEY")

def get_logs_directory() -> Path:
    """Get the logs directory from environment variables"""
    config = setup_config()
    return Path(config.output_dir)

def sanitize_folder_name(name):
    """Sanitize folder name to ensure consistency between generation and retrieval"""
    return re.sub(r'[^\w\-]', '_', name)

def get_mounted_subdirectories():
    """Obține lista subdirectoarelor din volumul montat pentru scanare"""
    mounted_dir = Path(MOUNTED_SRC_DIR)
    if not mounted_dir.exists() or not mounted_dir.is_dir():
        return []
    
    subdirs = []
    for item in mounted_dir.iterdir():
        if item.is_dir():
            subdirs.append({
                'path': str(item),
                'name': item.name
            })
    
    return subdirs

def get_analyzed_folders():
    """Get list of all analyzed folders"""
    logs_dir = get_logs_directory()
    
    if not logs_dir.exists():
        return []
    
    folders = []
    for folder in logs_dir.iterdir():
        if folder.is_dir() and folder.name.endswith("_logs"):
            try:
                latest_file = max(folder.glob('**/*'), key=lambda x: x.stat().st_mtime if x.is_file() else 0)
                timestamp = latest_file.stat().st_mtime if latest_file.is_file() else 0
            except ValueError:
                timestamp = 0
                
            vuln_count = 0
            for json_file in folder.glob('*.json'):
                try:
                    with open(json_file, 'r') as f:
                        vulns = json.load(f)
                        vuln_count += len(vulns)
                except:
                    pass
            
            folder_name = folder.name
            if folder_name.endswith("_logs"):
                folder_name = folder_name[:-5]
            
            folders.append({
                'id': folder.name,
                'name': folder_name,
                'timestamp': timestamp,
                'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)),
                'vulnerability_count': vuln_count
            })
    
    folders.sort(key=lambda x: x['timestamp'], reverse=True)
    return folders

def get_folder_details(folder_id):
    """Get details for a specific analysis folder"""
    logs_dir = get_logs_directory()
    folder_path = logs_dir / folder_id
    
    if not folder_path.exists() or not folder_path.is_dir():
        return None
    
    vulnerabilities = []
    
    for json_file in folder_path.glob('*.json'):
        try:
            with open(json_file, 'r') as f:
                vulns = json.load(f)
                vulnerabilities.extend(vulns)
        except:
            pass
    
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
    
    vuln_types = {}
    for vuln in vulnerabilities:
        vuln_type = vuln.get('vulnerability_type', 'Unknown')
        if vuln_type not in vuln_types:
            vuln_types[vuln_type] = 0
        vuln_types[vuln_type] += 1
    
    return {
        'id': folder_id,
        'name': folder_id[:-5] if folder_id.endswith('_logs') else folder_id,
        'vulnerabilities': vulnerabilities,
        'severity_counts': severity_counts,
        'vulnerability_types': vuln_types,
        'total_vulnerabilities': len(vulnerabilities)
    }

def run_scan_job(src_dir, openai_key, model_name, job_id, enable_codeql='true', codeql_language='javascript'):
    """Run a scan job in a separate process"""
    JOBS[job_id]['status'] = 'running'
    
    try:
        env = os.environ.copy()
        env['OPENAI_API_KEY'] = openai_key or ENTRYPOINT_API_KEY
        env['SRC_DIR'] = src_dir
        env['OUTPUT_DIR'] = str(get_logs_directory())
        
        project_name = Path(src_dir).name
        env['PROJECT_NAME'] = project_name
        
        if model_name:
            env['OPENAI_MODEL'] = model_name
        env['ENABLE_CODEQL'] = enable_codeql
        env['CODEQL_LANGUAGE'] = codeql_language
        
        process = subprocess.Popen(
            [sys.executable, os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                'main.py'
            )],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            JOBS[job_id]['status'] = 'completed'
            JOBS[job_id]['output'] = stdout.decode('utf-8', errors='ignore')
            
            sanitized_name = sanitize_folder_name(project_name)
            JOBS[job_id]['results_folder'] = f"{sanitized_name}_logs"
        else:
            JOBS[job_id]['status'] = 'failed'
            JOBS[job_id]['error'] = stderr.decode('utf-8', errors='ignore')
    
    except Exception as e:
        JOBS[job_id]['status'] = 'failed'
        JOBS[job_id]['error'] = str(e)

@app.route('/')
def index():
    """Home page with list of analyzed folders"""
    folders = get_analyzed_folders()
    return render_template('index.html', folders=folders)

@app.route('/analysis/<folder_id>')
def analysis_details(folder_id):
    """Show analysis results for a specific folder"""
    details = get_folder_details(folder_id)
    if not details:
        # Încercăm să găsim directorul de log cu alt pattern de sanitizare
        logs_dir = get_logs_directory()
        potential_matches = []
        
        # Căutăm toate directoarele de log
        for folder in logs_dir.iterdir():
            if folder.is_dir() and folder.name.endswith("_logs"):
                potential_matches.append(folder.name)
        
        # Dacă există orice potrivire, redirecționăm la prima
        if potential_matches:
            flash(f"Folder original negăsit. Redirecționat către {potential_matches[0]}", "warning")
            return redirect(url_for('analysis_details', folder_id=potential_matches[0]))
        
        abort(404)
    
    return render_template('analysis.html', details=details)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan a new folder"""
    if request.method == 'POST':
        folder_path = request.form.get('folder_path')
        openai_key = request.form.get('openai_key')
        model_name = request.form.get('model_name')
        enable_codeql = request.form.get('enable_codeql', 'true')
        codeql_language = request.form.get('codeql_language', 'javascript')

        if not folder_path:
            flash('Please provide folder path', 'error')
            return redirect(url_for('scan'))
        
        if not openai_key and not ENTRYPOINT_API_KEY:
            flash('Please provide OpenAI API key or ensure it was provided at container startup', 'error')
            return redirect(url_for('scan'))
        
        if not os.path.isdir(folder_path):
            flash(f'Folder {folder_path} does not exist', 'error')
            return redirect(url_for('scan'))
        
        job_id = str(int(time.time()))
        JOBS[job_id] = {
            'status': 'starting',
            'folder': folder_path,
            'model': model_name or 'gpt-4-turbo',
            'codeql': enable_codeql == 'true',
            'codeql_language': codeql_language,
            'time': time.time()
        }
        
        thread = threading.Thread(
            target=run_scan_job,
            args=(folder_path, openai_key, model_name, job_id, enable_codeql, codeql_language)
        )
        thread.daemon = True
        thread.start()
        
        flash('Scan job started', 'success')
        return redirect(url_for('job_status', job_id=job_id))
    
    mounted_subdirs = get_mounted_subdirectories()
    return render_template('scan.html', 
                          has_entrypoint_key=bool(ENTRYPOINT_API_KEY),
                          mounted_subdirs=mounted_subdirs,
                          mounted_dir=MOUNTED_SRC_DIR)

@app.route('/job/<job_id>')
def job_status(job_id):
    """Check the status of a job"""
    if job_id not in JOBS:
        abort(404)
    return render_template('job_status.html', job=JOBS[job_id], job_id=job_id)

@app.route('/api/job/<job_id>')
def api_job_status(job_id):
    """API endpoint to check job status"""
    if job_id not in JOBS:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(JOBS[job_id])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')