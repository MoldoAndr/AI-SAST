"""
Enhanced file discovery module for AI_SAST.

Discovers relevant files for security scanning with advanced heuristics.
Maintains compatibility with the existing project structure.
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import List, Set, Dict, Tuple, Optional
import hashlib
import mimetypes
from concurrent.futures import ThreadPoolExecutor
from rich.progress import Progress

from .openai_client import get_openai_client, call_openai_with_retry

logger = logging.getLogger("ai_sast")

FILE_CATEGORIES = {
    "frontend_markup": {
        ".html", ".htm", ".xhtml", ".ejs", ".hbs", ".pug", ".njk", ".cshtml", ".razor",
        ".vue", ".svelte", ".astro", ".jsx", ".tsx"
    },
    "frontend_script": {
        ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".coffee"
    },
    "frontend_style": {
        ".css", ".scss", ".sass", ".less", ".styl"
    },
    "backend_script": {
        ".php", ".py", ".rb", ".pl", ".go", ".java", ".cs", ".js", ".ts"
    },
    "data": {
        ".json", ".yml", ".yaml", ".xml", ".toml", ".csv", ".graphql", ".gql"
    },
    "config": {
        ".config", ".conf", ".ini", ".env", ".cfg", ".properties", ".lock", ".htaccess",
        ".babelrc", ".eslintrc", ".prettierrc"
    }
}

HIGH_RISK_EXTENSIONS = {
    '.php', '.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.html', '.htm', 
    '.vue', '.svelte', '.aspx', '.cshtml', '.jsp', '.ejs'
}

EXCLUDED_DIRS = {
    'node_modules', 'bower_components', 'vendor', 'packages', 'jspm_packages',
    'lib', '.npm', '.pnpm', '.yarn', 'venv', '.venv', 'env', 'ENV', 'virtualenv',
    '__pycache__', '.pytest_cache', '.rts2_cache', '.sass-cache', '.parcel-cache',
    
    'dist', 'build', 'out', 'public/build', 'public/dist', '.output', 'release',
    '.next', '.nuxt', '.svelte-kit', '.cache', 'coverage', 'docs', 'storybook-static',
    
    '.git', '.hg', '.svn', '.github', '.gitlab', '.circleci', '.jenkins',
    
    'assets/images', 'public/images', 'static/images', 'img', 'icons',
    'assets/videos', 'public/videos', 'static/videos', 'video', 'media',
    'assets/fonts', 'public/fonts', 'static/fonts', 'fonts',
    
    'locales', 'translations', 'i18n', '.storybook'
}

EXCLUDED_PATTERNS = [
    r'.*\.min\.(js|css)$',
    r'.*\.bundle\.(js|css)$',
    r'.*\.umd\.(js|ts)$',
    r'.*\.compiled\.(js|ts|jsx|tsx)$',
    r'.*\.prod\.(js|ts|jsx|tsx)$',
    r'.*\.(d|gen|generated)\.(ts|js)$',
    
    r'.*\.(test|spec|e2e|cy|stories|example|mock|fixture)\.(js|ts|jsx|tsx)$',
    r'.*test.*\.(js|ts|jsx|tsx)$',
    r'.*spec.*\.(js|ts|jsx|tsx)$',
    
    r'.*\.md$',
    r'.*\.mdx$',
    r'.*\.txt$',
    r'^LICENSE$',
    r'^README.*$',
    r'^CHANGELOG.*$',
    r'^CONTRIBUTING.*$',
    
    r'.*\.(jpg|jpeg|png|gif|svg|webp|bmp|ico|tiff|avif|pdf)$',
    r'.*\.(mp3|mp4|webm|ogg|wav|flac|aac|mov|avi)$',
    r'.*\.(ttf|woff|woff2|eot|otf)$',
    r'.*\.(zip|tar|gz|bz2|7z|rar)$',
    
    r'.*\.d\.ts$',
    r'.*\.module\.css$',
]

HIGH_RISK_PATTERNS = [
    r'(user(Input|Data|Content)|params\.|req\.body|req\.query|req\.params|formData)',
    r'(document\.write|\.innerHTML|\.outerHTML|\$\(.*\)\.html\()',
    r'(eval\(|setTimeout\(.*,|setInterval\(.*,|new Function\()',
    
    r'(cookies|localStorage|sessionStorage|authToken|jwt|password|credential)',
    
    r'(executeQuery|\.query\(|\.sql\(|mongoose\.|sequelize\.|knex\.|mongodb\.)',
    
    r'(fetch\(|axios\.|http\.|https\.|ajax\(|XMLHttpRequest)',
    
    r'(auth|login|logout|register|signIn|signUp|authenticate|authorize|role)',
    
    r'(fs\.|readFile|writeFile|unlink|readdir|mkdir)',
    
    r'(innerHTML|outerHTML|insertAdjacentHTML|document\.write)',
]

SECURITY_DEFENSE_PATTERNS = [
    r'(sanitize|escape|encode|validate|DOMPurify|helmet|CSP|xss|csrf|cors)',
    r'(encodeURI|encodeURIComponent|htmlspecialchars|strip_tags)',
]

FRONTEND_EXTENSIONS = set()
for category, extensions in FILE_CATEGORIES.items():
    FRONTEND_EXTENSIONS.update(extensions)


def get_file_category(file_path: Path) -> Optional[str]:
    """
    Determină categoria unui fișier bazată pe extensia sa.
    
    Args:
        file_path: Calea către fișier
        
    Returns:
        str|None: Categoria fișierului sau None dacă nu este recunoscută
    """
    ext = file_path.suffix.lower()
    
    for category, extensions in FILE_CATEGORIES.items():
        if ext in extensions:
            return category
    
    return None


def is_binary_file(file_path: Path) -> bool:
    """
    Verifică dacă fișierul este binar.
    
    Args:
        file_path: Calea către fișier
        
    Returns:
        bool: True dacă fișierul este binar, False altfel
    """
    mime, _ = mimetypes.guess_type(str(file_path))
    if mime:
        return not mime.startswith('text/') and not mime in ['application/json', 'application/xml', 'application/javascript']
    
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except Exception:
        return False


def calculate_risk_score(file_path: Path, content: str) -> Tuple[float, Dict[str, List[int]]]:
    """
    Calculează un scor de risc pentru un fișier bazat pe conținutul său.
    
    Args:
        file_path: Calea către fișier
        content: Conținutul fișierului
        
    Returns:
        Tuple[float, Dict[str, List[int]]]: Scor de risc (0.0-1.0) și detalii despre pattern-urile identificate
    """
    ext = file_path.suffix.lower()
    category = get_file_category(file_path)
    
    base_score = 0.1
    
    if ext in HIGH_RISK_EXTENSIONS:
        base_score = 0.4
    
    if category in ['frontend_script', 'backend_script']:
        base_score = max(base_score, 0.3)
    elif category in ['frontend_markup']:
        base_score = max(base_score, 0.25)
    
    risk_patterns_found = {}
    for pattern in HIGH_RISK_PATTERNS:
        matches = list(re.finditer(pattern, content))
        if matches:
            line_numbers = [content[:m.start()].count('\n') + 1 for m in matches]
            risk_patterns_found[pattern] = line_numbers
    
    defense_patterns_found = {}
    for pattern in SECURITY_DEFENSE_PATTERNS:
        matches = list(re.finditer(pattern, content))
        if matches:
            line_numbers = [content[:m.start()].count('\n') + 1 for m in matches]
            defense_patterns_found[pattern] = line_numbers
    
    pattern_score = min(0.6, len(risk_patterns_found) * 0.1)
    defense_reduction = min(0.3, len(defense_patterns_found) * 0.05)
    
    final_score = base_score + pattern_score - defense_reduction
    final_score = max(0.0, min(1.0, final_score))
    
    return final_score, risk_patterns_found


def is_relevant_file(file_path: Path, min_risk_score: float = 0.1) -> Tuple[bool, float, Dict]:
    """
    Verifică dacă un fișier este relevant pentru scanarea de securitate.
    
    Args:
        file_path: Calea către fișier
        min_risk_score: Scorul minim de risc pentru a fi considerat relevant
        
    Returns:
        Tuple[bool, float, Dict]: (Este relevant, scor de risc, detalii)
    """
    if file_path.suffix.lower() not in FRONTEND_EXTENSIONS:
        return False, 0.0, {}
    
    for part in file_path.parts:
        if part in EXCLUDED_DIRS:
            return False, 0.0, {}
    
    for pattern in EXCLUDED_PATTERNS:
        if re.match(pattern, file_path.name):
            return False, 0.0, {}
    
    if is_binary_file(file_path):
        return False, 0.0, {}
        
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        if len(content) > 100000:
            lines = content.splitlines()
            if len(lines) > 1000:
                content = '\n'.join(lines[:500] + lines[-500:])
        
        risk_score, risk_details = calculate_risk_score(file_path, content)
        
        return risk_score >= min_risk_score, risk_score, {
            "risk_score": risk_score,
            "patterns_found": risk_details
        }
    except Exception as e:
        logger.debug(f"Error analyzing {file_path}: {str(e)}")
        return True, 0.2, {"error": str(e)}


def find_entry_points(files: List[Path]) -> List[Path]:
    """
    Identifică fișierele care sunt posibile entry points în aplicație.
    
    Args:
        files: Lista de fișiere
        
    Returns:
        List[Path]: Lista de fișiere considerate entry points
    """
    entry_points = []
    entry_point_patterns = [
        r'(index|main|app)\.(js|ts|jsx|tsx|html|php|py)$',
        r'server\.(js|ts|py|rb)$',
        r'routes?\.(js|ts)$',
        r'controller\.js$',
        r'handler\.js$',
        r'middleware\.js$',
        r'(login|auth|user|admin)\.(js|php|py)$'
    ]
    
    for file in files:
        for pattern in entry_point_patterns:
            if re.search(pattern, file.name.lower()):
                entry_points.append(file)
                break
    
    return entry_points


def analyze_file_content(file_path: Path) -> Tuple[float, Dict]:
    """
    Analizează conținutul unui fișier pentru a determina riscul de securitate.
    
    Args:
        file_path: Calea către fișier
        
    Returns:
        Tuple[float, Dict]: (Scor de risc, detalii)
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        risk_score, risk_details = calculate_risk_score(file_path, content)
        return risk_score, {
            "risk_score": risk_score,
            "patterns_found": risk_details,
            "file_size": len(content),
            "line_count": content.count('\n') + 1
        }
    except Exception as e:
        logger.debug(f"Error analyzing content of {file_path}: {str(e)}")
        return 0.2, {"error": str(e)}


def filter_files_with_ai(files: List[Path], client) -> List[Path]:
    """
    Folosește OpenAI pentru a filtra fișierele cu potențiale vulnerabilități.
    Această implementare menține compatibilitatea cu cod existent.
    
    Args:
        files: Lista de fișiere
        client: Clientul OpenAI
        
    Returns:
        List[Path]: Lista de fișiere filtrate
    """
    file_list = [str(f).replace('\\', '/') for f in files]
    
    if len(file_list) > 100:
        dir_files = {}
        for file in file_list:
            dirname = os.path.dirname(file)
            if dirname not in dir_files:
                dir_files[dirname] = []
            dir_files[dirname].append(os.path.basename(file))
        
        dir_summary = []
        for dirname, files in dir_files.items():
            dir_summary.append(f"{dirname}: {len(files)} files")
            examples = files[:5]
            if examples:
                dir_summary.append("  Examples: " + ", ".join(examples))
            if len(files) > 5:
                dir_summary.append(f"  ... and {len(files) - 5} more files")
        
        file_summary = "\n".join(dir_summary)
    else:
        file_summary = "\n".join(file_list)
    
    entry_points = find_entry_points(files)
    entry_point_list = [str(f) for f in entry_points]
    
    file_categories = {}
    for file in files:
        category = get_file_category(file)
        if category not in file_categories:
            file_categories[category] = []
        file_categories[category].append(str(file))
    
    prompt = f"""You are a cybersecurity expert specializing in frontend security.
I have a list of files from a frontend project and need you to identify which ones might 
contain security vulnerabilities that should be analyzed.

Here's the list of files:
{file_summary}

Additional context:
- Entry points (files that might handle user input directly): {', '.join(entry_point_list[:10])} {f'and {len(entry_point_list) - 10} more' if len(entry_point_list) > 10 else ''}
- File categories: {', '.join(f'{cat}: {len(files)}' for cat, files in file_categories.items() if cat)}

Please analyze this list and return ONLY the paths of files that:
1. Are likely to contain code that processes user input
2. Could contain common frontend vulnerabilities like XSS, CSRF, insecure authentication, etc.
3. Handle sensitive data or operations

Return the file paths only, one per line, without any explanation or commentary.
Only include files that have the highest likelihood of containing vulnerabilities.
"""

    try:
        response = call_openai_with_retry(
            client=client,
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specialized in frontend security."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=4000
        )
        
        filtered_paths = response.choices[0].message.content.strip().split('\n')
        
        valid_paths = []
        original_paths_str = {str(f) for f in files}
        
        for p in filtered_paths:
            p = p.strip()
            if not p or p.startswith("#") or p.startswith("//"):
                continue
                
            if p in original_paths_str:
                valid_paths.append(p)
            else:
                for orig_p in original_paths_str:
                    if orig_p.endswith(p) or p.endswith(orig_p):
                        valid_paths.append(orig_p)
                        break
        
        result = [Path(p) for p in valid_paths]
        
        if len(result) < len(files) * 0.1:
            logger.warning("AI filtering returned too few files, using manual filtering as fallback")
            return [f for f in files if is_relevant_file(f)[0]]
        
        return result
    
    except Exception as e:
        logger.error(f"Error during AI filtering: {str(e)}")
        return [f for f in files if is_relevant_file(f)[0]]


def manual_risk_filtering(files: List[Path], min_risk_score: float = 0.3) -> List[Path]:
    """
    Filtrare manuală a fișierelor folosind euristici.
    
    Args:
        files: Lista de fișiere
        min_risk_score: Scorul minim de risc pentru a include un fișier
        
    Returns:
        List[Path]: Lista de fișiere filtrate
    """
    filtered_files = []
    
    for file in files:
        is_relevant, score, _ = is_relevant_file(file, min_risk_score)
        if is_relevant:
            filtered_files.append(file)
    
    entry_points = find_entry_points(files)
    for entry in entry_points:
        if entry not in filtered_files:
            filtered_files.append(entry)
    
    return filtered_files


def analyze_files_in_parallel(files: List[Path], min_risk_score: float = 0.3, max_workers: int = 10) -> List[Path]:
    """
    Analizează fișierele în paralel pentru a identifica riscurile de securitate.
    
    Args:
        files: Lista de fișiere
        min_risk_score: Scorul minim de risc pentru a include un fișier
        max_workers: Numărul maxim de threaduri
        
    Returns:
        List[Path]: Lista fișierelor relevante
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(is_relevant_file, file, min_risk_score): file for file in files}
        
        for future in future_to_file:
            file = future_to_file[future]
            try:
                is_relevant, _, _ = future.result()
                if is_relevant:
                    results.append(file)
            except Exception as e:
                logger.error(f"Error analyzing {file}: {str(e)}")
    
    return results


def discover_relevant_files(directory: Path, progress: Progress, task_id) -> List[Path]:
    """
    Descoperă fișierele relevante pentru scanarea de securitate.
    Menține compatibilitatea cu semnătura funcției originale.
    
    Args:
        directory: Directorul de scanat
        progress: Obiectul de progres pentru actualizarea barei de progres
        task_id: ID-ul taskului pentru bara de progres
        
    Returns:
        List[Path]: Lista de fișiere relevante
    """
    logger.info(f"Discovering files in {directory}")
    progress.update(task_id, description="[cyan]Listing all files...", completed=10)
    
    all_files = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        
        root_path = Path(root)
        for file in files:
            file_path = root_path / file
            if file_path.is_file():
                all_files.append(file_path)
    
    logger.info(f"Found {len(all_files)} files in total")
    
    progress.update(task_id, description="[cyan]Initial filtering...", completed=20)
    
    initial_filtered = []
    for file in all_files:
        if file.suffix.lower() in FRONTEND_EXTENSIONS:
            exclude = False
            for pattern in EXCLUDED_PATTERNS:
                if re.match(pattern, file.name):
                    exclude = True
                    break
            
            for part in file.parts:
                if part in EXCLUDED_DIRS:
                    exclude = True
                    break
            
            if not exclude:
                initial_filtered.append(file)
    
    logger.info(f"Initial filtering: {len(initial_filtered)} files remain after basic filtering")
    
    progress.update(task_id, description="[cyan]Analyzing files for security risks...", completed=40)
    filtered_files = analyze_files_in_parallel(
        initial_filtered, 
        min_risk_score=0.2,
        max_workers=min(os.cpu_count() or 4, 10)
    )
    
    if len(filtered_files) > 100:
        progress.update(task_id, description="[cyan]Using AI to identify high-risk files...", completed=60)
        client = get_openai_client()
        filtered_files = filter_files_with_ai(filtered_files, client)
    
    logger.info(f"Final filtering: {len(filtered_files)} files selected for vulnerability scanning")
    progress.update(task_id, description=f"[green]Found {len(filtered_files)} relevant files", completed=90)
    
    return filtered_files


def discover_relevant_files_with_scores(directory: Path, progress: Progress, task_id) -> Tuple[List[Path], Dict[Path, float]]:
    """
    Versiune extinsă care returnează și scorurile de risc.
    Poate fi utilizată în viitoarele versiuni când codul poate fi adaptat.
    
    Args:
        directory: Directorul de scanat
        progress: Obiectul de progres
        task_id: ID-ul taskului
        
    Returns:
        Tuple[List[Path], Dict[Path, float]]: (Lista de fișiere relevante, scoreuri)
    """
    files = discover_relevant_files(directory, progress, task_id)
    
    scores = {}
    for file in files:
        try:
            _, score, _ = is_relevant_file(file)
            scores[file] = score
        except Exception:
            scores[file] = 0.5
    
    return files, scores