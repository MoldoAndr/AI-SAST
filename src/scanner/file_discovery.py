"""
File discovery module for AI_SAST.

Discovers relevant files for security scanning and filters out irrelevant files.
"""

import os
import re
import logging
from pathlib import Path
from typing import List, Set, Dict
import json
from tqdm import tqdm
from rich.progress import Progress

from .openai_client import get_openai_client


# Define frontend file extensions to analyze
FRONTEND_EXTENSIONS = {
    # HTML and templates
    '.html', '.htm', '.xhtml', '.ejs', '.hbs', '.pug', '.njk', '.cshtml', '.razor',
    # JavaScript
    '.js', '.jsx', '.mjs', '.cjs', 
    # TypeScript
    '.ts', '.tsx',
    # Component frameworks
    '.vue', '.svelte', '.astro',
    # Styles that might contain code
    '.css', '.scss', '.sass', '.less',
    # Configuration files
    '.json', '.yml', '.yaml', '.toml',
}

# Common directories to exclude
EXCLUDED_DIRS = {
    'node_modules', 'dist', 'build', '.git', 'coverage', 'out', '.next', '.nuxt', 
    '.cache', '.output', '.svelte-kit', '__pycache__', '.venv', 'venv',
    'vendor', 'bower_components', 'jspm_packages', 'public/assets', 'static/assets'
}

# File patterns to exclude
EXCLUDED_PATTERNS = [
    r'.*\.min\.(js|css)$',  # Minified files
    r'.*\.bundle\.(js|css)$',  # Bundled files
    r'.*\.test\.(js|ts|jsx|tsx)$',  # Test files
    r'.*\.spec\.(js|ts|jsx|tsx)$',  # Test spec files
    r'.*\.stories\.(js|ts|jsx|tsx)$',  # Storybook files
    r'.*\.d\.ts$',  # TypeScript definition files
]

logger = logging.getLogger("ai_sast")


def is_relevant_file(path: Path) -> bool:
    """
    Check if a file is relevant for security scanning.
    
    Args:
        path: Path to the file
        
    Returns:
        bool: True if the file is relevant, False otherwise
    """
    # Check if the file extension is in our list
    if path.suffix.lower() not in FRONTEND_EXTENSIONS:
        return False
    
    # Check if the file is in an excluded directory
    for part in path.parts:
        if part in EXCLUDED_DIRS:
            return False
    
    # Check excluded patterns
    for pattern in EXCLUDED_PATTERNS:
        if re.match(pattern, path.name):
            return False
    
    return True


def get_all_files(directory: Path) -> List[Path]:
    """
    Get all files in a directory recursively.
    
    Args:
        directory: Directory to scan
        
    Returns:
        List[Path]: List of all file paths
    """
    all_files = []
    
    for root, dirs, files in os.walk(directory):
        # Remove excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        
        root_path = Path(root)
        for file in files:
            file_path = root_path / file
            if file_path.is_file():
                all_files.append(file_path)
    
    return all_files


def filter_files_with_ai(files: List[Path], client) -> List[Path]:
    """
    Use OpenAI to filter out files that are unlikely to contain vulnerabilities.
    
    Args:
        files: List of file paths
        client: OpenAI client
        
    Returns:
        List[Path]: Filtered list of file paths
    """
    # Convert paths to relative paths for better readability
    file_list = [str(f).replace('\\', '/') for f in files]
    
    # If there are too many files, let's chunk them for better analysis
    if len(file_list) > 100:
        # Group files by directory for better context
        dir_files = {}
        for file in file_list:
            dirname = os.path.dirname(file)
            if dirname not in dir_files:
                dir_files[dirname] = []
            dir_files[dirname].append(os.path.basename(file))
        
        # Create a summary of directories and file counts
        dir_summary = []
        for dirname, files in dir_files.items():
            dir_summary.append(f"{dirname}: {len(files)} files")
            # Add up to 5 examples per directory
            examples = files[:5]
            if examples:
                dir_summary.append("  Examples: " + ", ".join(examples))
            if len(files) > 5:
                dir_summary.append(f"  ... and {len(files) - 5} more files")
        
        file_summary = "\n".join(dir_summary)
    else:
        # Just use the full list if it's not too large
        file_summary = "\n".join(file_list)
    
    prompt = f"""You are a cybersecurity expert specializing in frontend security.
I have a list of files from a frontend project and need you to identify which ones might 
contain security vulnerabilities that should be analyzed.

Here's the list of files:
{file_summary}

Please analyze this list and return ONLY the paths of files that:
1. Are likely to contain code that processes user input
2. Could contain common frontend vulnerabilities like XSS, CSRF, insecure authentication, etc.
3. Handle sensitive data or operations

Return the file paths only, one per line, without any explanation or commentary.
Only include files that have the highest likelihood of containing vulnerabilities.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specialized in frontend security."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=4000
        )
        
        filtered_paths = response.choices[0].message.content.strip().split('\n')
        
        # Clean up paths and ensure they exist in the original list
        valid_paths = []
        original_paths_str = {str(f) for f in files}
        
        for p in filtered_paths:
            p = p.strip()
            if not p or p.startswith("#") or p.startswith("//"):
                continue
                
            # Try to find the path in our original list
            if p in original_paths_str:
                valid_paths.append(p)
            else:
                # Try to handle relative vs. absolute path issues
                for orig_p in original_paths_str:
                    if orig_p.endswith(p) or p.endswith(orig_p):
                        valid_paths.append(orig_p)
                        break
        
        # Convert back to Path objects
        result = [Path(p) for p in valid_paths]
        
        # If AI didn't return any valid paths or filtered too aggressively, 
        # use our manual filter as a fallback
        if len(result) < len(files) * 0.1:
            logger.warning("AI filtering returned too few files, using manual filtering as fallback")
            return [f for f in files if is_relevant_file(f)]
        
        return result
    
    except Exception as e:
        logger.error(f"Error during AI filtering: {str(e)}")
        # Fallback to manual filtering if AI fails
        return [f for f in files if is_relevant_file(f)]


def discover_relevant_files(directory: Path, progress: Progress, task_id) -> List[Path]:
    """
    Discover relevant files for security scanning.
    
    Args:
        directory: Directory to scan
        progress: Progress object for updating the progress bar
        task_id: Task ID for the progress bar
        
    Returns:
        List[Path]: List of relevant file paths
    """
    logger.info(f"Discovering files in {directory}")
    progress.update(task_id, description="[cyan]Listing all files...", completed=10)
    
    # Get all files
    all_files = get_all_files(directory)
    logger.info(f"Found {len(all_files)} files in total")
    
    # Initial filtering based on extensions and exclusions
    progress.update(task_id, description="[cyan]Filtering irrelevant files...", completed=30)
    filtered_files = [f for f in all_files if is_relevant_file(f)]
    logger.info(f"Initial filtering: {len(filtered_files)} files remain after basic filtering")
    
    # Use AI to further filter files if we have more than 10 files
    if len(filtered_files) > 10:
        progress.update(task_id, description="[cyan]Using AI to identify high-risk files...", completed=50)
        client = get_openai_client()
        filtered_files = filter_files_with_ai(filtered_files, client)
    
    logger.info(f"Final filtering: {len(filtered_files)} files selected for vulnerability scanning")
    progress.update(task_id, description=f"[green]Found {len(filtered_files)} relevant files", completed=90)
    
    return filtered_files