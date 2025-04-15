"""
File analyzer module for AI_SAST.

Analyzes relationships between files and identifies imports, dependencies, etc.
"""

import os
import re
import ast
import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any
from rich.progress import Progress

logger = logging.getLogger("ai_sast")


def analyze_javascript_imports(content: str) -> List[str]:
    """
    Analyze JavaScript/TypeScript imports.
    
    Args:
        content: File content
        
    Returns:
        List[str]: List of imported modules or files
    """
    imports = []
    
    # ES Module imports: import X from 'module'
    es_imports = re.findall(r'import\s+(?:(?:{[^}]+}|\*\s+as\s+\w+|\w+)(?:\s*,\s*(?:{[^}]+}|\*\s+as\s+\w+|\w+))*)?(?:\s+from)?\s+[\'"]([^\'"]+)[\'"]', content)
    imports.extend(es_imports)
    
    # CommonJS imports: require('module')
    require_imports = re.findall(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', content)
    imports.extend(require_imports)
    
    # Dynamic imports: import('module')
    dynamic_imports = re.findall(r'import\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', content)
    imports.extend(dynamic_imports)
    
    return imports


def analyze_python_imports(content: str) -> List[str]:
    """
    Analyze Python imports.
    
    Args:
        content: File content
        
    Returns:
        List[str]: List of imported modules
    """
    imports = []
    
    try:
        tree = ast.parse(content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.append(name.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
    except SyntaxError:
        # Not valid Python code
        pass
    
    return imports


def analyze_html_imports(content: str) -> List[str]:
    """
    Analyze HTML imports (scripts, stylesheets, etc.).
    
    Args:
        content: File content
        
    Returns:
        List[str]: List of imported resources
    """
    imports = []
    
    # JavaScript files
    script_srcs = re.findall(r'<script[^>]*src=[\'"]([^\'"]+)[\'"]', content)
    imports.extend(script_srcs)
    
    # CSS files
    css_hrefs = re.findall(r'<link[^>]*rel=[\'"]stylesheet[\'"][^>]*href=[\'"]([^\'"]+)[\'"]', content)
    imports.extend(css_hrefs)
    
    # Imports in JS framework templates
    # Vue single file components
    vue_imports = re.findall(r'import\s+.+\s+from\s+[\'"]([^\'"]+)[\'"]', content)
    imports.extend(vue_imports)
    
    return imports


def get_file_imports(file_path: Path, content: str) -> List[str]:
    """
    Get imports from a file based on its extension.
    
    Args:
        file_path: Path to the file
        content: File content
        
    Returns:
        List[str]: List of imported modules or files
    """
    extension = file_path.suffix.lower()
    
    if extension in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte'}:
        return analyze_javascript_imports(content)
    elif extension == '.py':
        return analyze_python_imports(content)
    elif extension in {'.html', '.htm', '.xhtml', '.ejs', '.hbs', '.pug', '.njk', '.cshtml'}:
        return analyze_html_imports(content)
    
    return []


def resolve_import_path(base_path: Path, import_path: str) -> Path:
    """
    Resolve an import path to an absolute path.
    
    Args:
        base_path: Path to the file containing the import
        import_path: Import path
        
    Returns:
        Path: Resolved absolute path
    """
    # Handle relative imports
    if import_path.startswith('.'):
        # Get the directory of the base file
        base_dir = base_path.parent
        
        # Remove leading dots and slashes
        clean_path = import_path.lstrip('./').rstrip('/')
        
        # Handle parent directory references
        if import_path.startswith('..'):
            parts = import_path.split('/')
            parent_count = 0
            
            for part in parts:
                if part == '..':
                    parent_count += 1
                else:
                    break
            
            # Go up parent_count directories
            for _ in range(parent_count):
                base_dir = base_dir.parent
            
            # Remove the parent directory parts from the path
            clean_path = '/'.join(parts[parent_count:])
        
        # Combine the paths
        resolved_path = base_dir / clean_path
        return resolved_path
    
    # Handle absolute imports
    elif import_path.startswith('/'):
        # Use the import path as is
        return Path(import_path)
    
    # Handle package imports (just return the import path)
    else:
        return Path(import_path)


def analyze_file_relationships(files: List[Path], progress: Progress, task_id) -> Dict[Path, List[Path]]:
    """
    Analyze relationships between files.
    
    Args:
        files: List of files to analyze
        progress: Progress object for updating the progress bar
        task_id: Task ID for the progress bar
        
    Returns:
        Dict[Path, List[Path]]: Dictionary mapping files to their dependencies
    """
    progress.update(task_id, description="[cyan]Analyzing file relationships...", completed=0)
    
    relationships = {}
    file_count = len(files)
    
    # Create a mapping of file paths to their canonical paths
    file_map = {file.resolve(): file for file in files}
    
    # Read and analyze each file
    for i, file in enumerate(files):
        progress.update(task_id, description=f"[cyan]Analyzing {file.name}...", completed=(i / file_count) * 100)
        
        try:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Get imports from the file
            imports = get_file_imports(file, content)
            
            # Resolve import paths
            resolved_imports = []
            for import_path in imports:
                try:
                    # Try different extensions for the import path
                    resolved_path = resolve_import_path(file, import_path)
                    
                    # Try to find the file in our file list
                    for ext in ['.js', '.jsx', '.ts', '.tsx', '.py', '.html', '.vue', '.svelte']:
                        test_path = resolved_path.with_suffix(ext)
                        if test_path.resolve() in file_map:
                            resolved_imports.append(file_map[test_path.resolve()])
                            break
                        
                        # Also try without extension
                        if resolved_path.resolve() in file_map:
                            resolved_imports.append(file_map[resolved_path.resolve()])
                            break
                except Exception as e:
                    logger.debug(f"Error resolving import {import_path} in {file}: {str(e)}")
            
            relationships[file] = resolved_imports
        except Exception as e:
            logger.warning(f"Error analyzing {file}: {str(e)}")
            relationships[file] = []
    
    progress.update(task_id, description="[green]File relationship analysis complete", completed=100)
    
    return relationships