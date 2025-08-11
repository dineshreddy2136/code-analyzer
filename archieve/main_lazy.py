#!/usr/bin/env python3
"""
Codebase Dependency Analyzer

A comprehensive search application that processes Python codebases (.whl/.zip files)
and analyzes function dependencies to output them in the correct order.

Features:
- Extract and process .whl/.zip codebases
- Fast file search with pattern matching
- Content search with regex support  
- Python function dependency analysis
- Dependency resolution and ordering
- Caching for improved performance
- Lazy analysis mode for large codebases

Usage:
    python codebase_dependency_analyzer.py <codebase.zip> <function_snippet.txt> [--lazy]
"""

import os
import sys
import re
import ast
import json
import logging
import zipfile
import hashlib
import tempfile
import argparse
import fnmatch
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
import shutil
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import optional dependencies
try:
    import wheel
    WHEEL_SUPPORT = True
except ImportError:
    WHEEL_SUPPORT = False

# Module-level constants
STDLIB_MODULES = {
    'secrets': ['randbelow', 'randbytes', 'token_bytes', 'token_hex', 'choice'],
    'random': ['randint', 'choice', 'shuffle', 'random', 'uniform', 'randrange'],
    'os': ['path', 'environ', 'getcwd', 'listdir', 'mkdir', 'remove', 'rename'],
    'sys': ['exit', 'argv', 'path', 'stdin', 'stdout', 'stderr'],
    'json': ['loads', 'dumps', 'load', 'dump'],
    'datetime': ['now', 'today', 'strptime', 'strftime'],
    'time': ['time', 'sleep', 'strftime', 'strptime'],
    'math': ['sqrt', 'pow', 'floor', 'ceil', 'sin', 'cos'],
    'hashlib': ['md5', 'sha1', 'sha256', 'sha512'],
    'uuid': ['uuid4', 'uuid1'],
    'base64': ['b64encode', 'b64decode'],
    'urllib': ['parse', 'request', 'error']
}

STDLIB_SUBMODULES = {
    'os.path': ['exists', 'join', 'dirname', 'basename', 'abspath', 'isfile', 'isdir'],
    'urllib.parse': ['urlencode', 'quote', 'unquote', 'urlparse', 'parse_qs'],
    'urllib.request': ['urlopen', 'Request'],
    'json.decoder': ['JSONDecodeError'],
    'xml.etree.ElementTree': ['parse', 'fromstring', 'tostring']
}

BUILTIN_METHODS = {
    'add', 'append', 'remove', 'pop', 'clear', 'update', 'get', 'set',
    'keys', 'values', 'items', 'copy', 'extend', 'insert', 'reverse',
    'sort', 'count', 'index', 'replace', 'split', 'join', 'strip',
    'startswith', 'endswith', 'lower', 'upper', 'title', 'capitalize',
    'format', 'encode', 'decode', 'find', 'rfind', 'isdigit', 'isalpha',
    'isupper', 'islower', 'isspace', 'exists', 'read', 'write', 'close',
    'appendleft', 'popleft', 'setdefault'
}

BUILTIN_ATTRS = {
    'append', 'extend', 'insert', 'pop', 'remove', 'clear', 'update', 'get', 'setdefault',
    'keys', 'values', 'items', 'copy', 'sort', 'reverse', 'format', 'join', 'split',
    'encode', 'decode', 'startswith', 'endswith', 'lower', 'upper', 'strip',
    'appendleft', 'popleft'
}

# File size and processing constants
MAX_FILE_SIZE_MB = 10
DEFAULT_MAX_FUNCTIONS = 10000
DEFAULT_MAX_WORKERS = 8


@dataclass(frozen=True)
class DependencyInfo:
    """Represents a function dependency. frozen=True makes it hashable."""
    short_name: str
    scope_tag: str  # 'CLASS_LOCAL', 'UNSCOPED', 'OBJ'
    owner: Optional[str] = None  # For OBJ scope, the object name

    def __iter__(self):
        """Allow tuple unpacking for backward compatibility"""
        return iter((self.short_name, self.scope_tag, self.owner))

    def __getitem__(self, index):
        """Allow tuple-like indexing for backward compatibility"""
        return (self.short_name, self.scope_tag, self.owner)[index]


@dataclass
class FileMatch:
    """Represents a file search match"""
    file_path: str
    line_number: int = 0
    line_content: str = ""
    match_score: float = 0.0


@dataclass
class FunctionInfo:
    """Information about a function"""
    name: str
    file_path: str
    line_number: int
    source_code: str
    dependencies: Set[DependencyInfo] = field(default_factory=set)
    calls: Set[str] = field(default_factory=set)
    imports: Set[str] = field(default_factory=set)
    signature: str = ""
    docstring: str = ""
    source_aliases: Dict[str, str] = field(default_factory=dict)
    kind: str = "inst"  # 'inst' | 'static' | 'class'


@dataclass
class SearchResult:
    """Search operation result"""
    matches: List[FileMatch]
    total_files_searched: int
    search_time: float
    pattern: str


class FileSearchEngine:
    """Fast file search engine with pattern matching and caching"""

    def __init__(self, root_dir: str, cache_enabled: bool = True):
        self.root_dir = Path(root_dir).resolve()
        self.cache_enabled = cache_enabled
        self._file_cache: Dict[str, List[str]] = {}
        self._ignore_patterns = {
            '__pycache__', '*.pyc', '.git', '.svn',
            '.DS_Store', '*.log', '.pytest_cache', '.mypy_cache'
        }
        self._all_files: Optional[List[str]] = None

    def add_ignore_pattern(self, pattern: str) -> None:
        """Add a pattern to ignore during file searches"""
        self._ignore_patterns.add(pattern)

    def _should_ignore(self, path: Path) -> bool:
        """Check if a path should be ignored"""
        for pattern in self._ignore_patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
            if pattern in str(path):
                return True
        return False

    def _get_all_files(self) -> List[str]:
        """Get all files in the directory, cached"""
        if self._all_files is not None:
            return self._all_files
            
        files = []
        for root, dirs, filenames in os.walk(self.root_dir):
            # Remove ignored directories in-place
            dirs[:] = [d for d in dirs if not self._should_ignore(Path(root) / d)]
            
            for filename in filenames:
                file_path = Path(root) / filename
                if not self._should_ignore(file_path):
                    rel_path = file_path.relative_to(self.root_dir)
                    files.append(str(rel_path))
                    
        files.sort()
        self._all_files = files
        return files

    def search_files(self, pattern: str, max_results: int = 1000) -> List[str]:
        """Search for files matching a pattern"""
        all_files = self._get_all_files()
        
        # Convert pattern to regex if it contains wildcards
        if '*' in pattern or '?' in pattern:
            regex_pattern = fnmatch.translate(pattern)
            regex = re.compile(regex_pattern, re.IGNORECASE)
            matches = [f for f in all_files if regex.match(f)]
        else:
            # Substring search
            pattern_lower = pattern.lower()
            matches = [f for f in all_files if pattern_lower in f.lower()]
            
        return matches[:max_results]


class ContentSearchEngine:
    """Content search engine with regex support"""

    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()

    def search_content(self, pattern: str, file_patterns: List[str] = None,
                         is_regex: bool = False, max_results: int = 1000) -> SearchResult:
        """Search for content within files"""
        start_time = time.time()
        matches = []
        files_searched = 0
        
        if is_regex:
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        else:
            # Escape special regex characters for literal search
            escaped_pattern = re.escape(pattern)
            regex = re.compile(escaped_pattern, re.IGNORECASE | re.MULTILINE)
            
        # Determine which files to search
        if file_patterns:
            files_to_search = []
            for file_pattern in file_patterns:
                files_to_search.extend(self._find_files_by_pattern(file_pattern))
        else:
            files_to_search = self._get_all_text_files()
            
        for file_path in files_to_search:
            if len(matches) >= max_results:
                break
                
            try:
                full_path = self.root_dir / file_path
                
                # Skip very large files to prevent memory issues
                file_stats = full_path.stat()
                max_file_size = MAX_FILE_SIZE_MB * 1024 * 1024  # Use constant
                if file_stats.st_size > max_file_size:
                    logging.warning(f"Skipping large file {file_path} ({file_stats.st_size / (1024*1024):.1f}MB) in content search")
                    continue
                    
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    files_searched += 1
                    # Read line-by-line for better memory efficiency
                    for line_num, line in enumerate(f, 1):
                        if regex.search(line):
                            matches.append(FileMatch(
                                file_path=str(file_path),
                                line_number=line_num,
                                line_content=line.strip(),
                                match_score=1.0
                            ))
                            
            except (UnicodeDecodeError, PermissionError, FileNotFoundError, OSError):
                # Skip files that can't be read due to encoding, permissions, or other OS errors
                continue
                
        search_time = time.time() - start_time
        return SearchResult(
            matches=matches,
            total_files_searched=files_searched,
            search_time=search_time,
            pattern=pattern
        )

    def _find_files_by_pattern(self, pattern: str) -> List[str]:
        """Find files matching a pattern"""
        files = []
        for root, _, filenames in os.walk(self.root_dir):
            for filename in filenames:
                if fnmatch.fnmatch(filename, pattern):
                    file_path = Path(root) / filename
                    rel_path = file_path.relative_to(self.root_dir)
                    files.append(str(rel_path))
        return files

    def _get_all_text_files(self) -> List[str]:
        """Get all text files for searching"""
        text_extensions = {'.py', '.java', '.cpp', '.c', '.h',
                         '.txt', '.md', '.rst', '.json', '.yaml', '.yml',
                         '.xml', '.html', '.css', '.sql', '.sh', '.bat'}
        
        files = []
        for root, _, filenames in os.walk(self.root_dir):
            for filename in filenames:
                file_path = Path(root) / filename
                if file_path.suffix.lower() in text_extensions:
                    rel_path = file_path.relative_to(self.root_dir)
                    files.append(str(rel_path))
                    
        return files


class PythonDependencyAnalyzer:
    """Analyzes Python code dependencies using AST"""

    def __init__(self, root_dir: str, max_functions_in_memory: int = DEFAULT_MAX_FUNCTIONS, enforce_memory_limit: bool = False):
        self.root_dir = Path(root_dir).resolve()
        self.max_functions_in_memory = max_functions_in_memory
        self.enforce_memory_limit = enforce_memory_limit
        self._lock = threading.Lock()  # For thread safety
        self.func_by_qname: Dict[str, FunctionInfo] = {}
        self.short_index: Dict[str, Set[str]] = defaultdict(set)
        self.module_of: Dict[str, str] = {}
        self.class_of: Dict[str, Optional[str]] = {}
        self.project_prefixes: Set[str] = set()
        self.module_aliases: Dict[str, Dict[str, str]] = defaultdict(dict)
        self.parsed_modules: Set[str] = set()
        self._discovered_modules: Set[str] = set()  # Track discovered modules

    def analyze_file(self, file_path: str) -> List[FunctionInfo]:
        """Analyze a Python file and extract function information"""
        file_path_obj = Path(file_path)
        
        if file_path_obj.is_absolute():
            full_path = file_path_obj
            try:
                relative_path = str(full_path.relative_to(self.root_dir))
            except ValueError:
                relative_path = full_path.name
        else:
            full_path = self.root_dir / file_path
            relative_path = file_path
        
        try:
            file_stats = full_path.stat()
            max_file_size = MAX_FILE_SIZE_MB * 1024 * 1024
            if file_stats.st_size > max_file_size:
                logging.warning(f"Skipping large file {relative_path} ({file_stats.st_size / (1024*1024):.1f}MB)")
                return []
                
            with open(full_path, 'r', encoding='utf-8') as f:
                source = f.read()
                
            tree = ast.parse(source)
            analyzer = _PythonASTAnalyzer(relative_path, source)
            analyzer.visit(tree)
            
            return analyzer.functions
            
        except (SyntaxError, UnicodeDecodeError, FileNotFoundError, OSError) as e:
            logging.warning(f"Could not parse {file_path}: {e}")
            return []

    def _discover_project_prefixes(self):
        """Finds the top-level package directories in the codebase."""
        if self.project_prefixes:
            return

        SKIP_TOPS = {'__pycache__'}
        def _is_meta_dir(name: str) -> bool:
            return name.endswith(('.dist-info', '.data', '.egg-info'))
            
        prefixes = set()
        discovered_modules = set()
        
        for root, _, files in os.walk(self.root_dir):
            for f in files:
                if f.endswith('.py'):
                    rel_path = Path(root).relative_to(self.root_dir) / f
                    rel_dir = Path(root).relative_to(self.root_dir)
                    
                    # Convert file path to module name
                    if f == '__init__.py':
                        # Package module
                        if rel_dir.parts:
                            module_name = '.'.join(rel_dir.parts)
                            discovered_modules.add(module_name)
                    else:
                        # Regular module
                        module_parts = list(rel_dir.parts) + [f[:-3]]  # Remove .py extension
                        if module_parts != ['']:
                            module_name = '.'.join(module_parts)
                            discovered_modules.add(module_name)
                    
                    # Track prefixes
                    if rel_dir.parts:
                        top = rel_dir.parts[0]
                        if top not in SKIP_TOPS and not _is_meta_dir(top):
                            prefixes.add(top)
        
        self.project_prefixes = prefixes
        self._discovered_modules = discovered_modules
        logging.info(f"Project prefixes (internal): {sorted(self.project_prefixes)}")

    def analyze_codebase(self) -> None:
        """Analyze the entire codebase with parallel processing for better performance"""
        python_files = []
        for root, _, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(self.root_dir)
                    python_files.append(str(rel_path))
                    
        logging.info(f"Analyzing {len(python_files)} Python files...")
        
        self._analysis_stats = {
            'total_files': len(python_files),
            'skipped_files': 0,
            'rejected_functions': 0,
            'parsed_functions': 0,
            'analysis_start_time': time.time()
        }
        
        if len(python_files) > 10:
            self._analyze_files_parallel(python_files)
        else:
            self._analyze_files_sequential(python_files)
            
        self._discover_project_prefixes()
        
        analysis_time = time.time() - self._analysis_stats['analysis_start_time']
        logging.info(f"Analysis complete: {self._analysis_stats['parsed_functions']} functions parsed in {analysis_time:.2f}s")
        if self._analysis_stats['skipped_files'] > 0:
            logging.warning(f"Skipped {self._analysis_stats['skipped_files']} files due to size/parse errors")
        if self._analysis_stats.get('rejected_functions', 0) > 0:
            logging.warning(f"Rejected {self._analysis_stats['rejected_functions']} functions due to memory limits")

    def analyze_on_demand(self, start_function_qname: str):
        """Initializes the analyzer for lazy mode and tries to load the initial function."""
        self._discover_project_prefixes()
        logging.info(f"Lazy analysis mode enabled. Starting with: {start_function_qname}")
        
        # Try to load the initial function's file
        module_to_parse = self._qname_to_module(start_function_qname)
        if module_to_parse:
            file_to_parse = self._module_to_file(module_to_parse)
            if file_to_parse:
                logging.info(f"[Lazy] Loading initial function from: {file_to_parse}")
                initial_functions = self.analyze_file(file_to_parse)
                self._store_functions(initial_functions)
                self.parsed_modules.add(module_to_parse)
            else:
                logging.warning(f"[Lazy] Could not find file for initial function module: {module_to_parse}")
        else:
            # Fallback: try to find by short name
            bucket = self.short_index.get(start_function_qname, set())
            if not bucket:
                logging.warning(f"[Lazy] Could not determine module for function: {start_function_qname}")

    def _is_internal(self, qname: str) -> bool:
        """Check if a qualified name is internal to the project"""
        top = qname.split('.', 1)[0]
        return top in self.project_prefixes

    def _analyze_files_sequential(self, python_files: List[str]) -> None:
        """Analyze files sequentially (for small codebases)"""
        for file_path in python_files:
            functions = self.analyze_file(file_path)
            self._store_functions(functions)

    def _analyze_files_parallel(self, python_files: List[str]) -> None:
        """Analyze files in parallel (for large codebases)"""
        max_workers = min(DEFAULT_MAX_WORKERS, len(python_files))
        total_files = len(python_files)
        processed_files = 0
        
        logging.info(f"Using {max_workers} parallel workers for analysis...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.analyze_file, file_path): file_path 
                for file_path in python_files
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    functions = future.result()
                    self._store_functions(functions)
                    processed_files += 1
                    
                    if processed_files % 50 == 0 or processed_files == total_files:
                        progress = (processed_files / total_files) * 100
                        logging.info(f"Progress: {processed_files}/{total_files} files analyzed ({progress:.1f}%)")
                        
                except Exception as e:
                    logging.warning(f"Error processing {file_path}: {e}")
                    processed_files += 1

    def _store_functions(self, functions: List[FunctionInfo]) -> None:
        """Store function information thread-safely with memory management"""
        with self._lock:
            current_count = len(self.func_by_qname)
            new_count = current_count + len(functions)
            
            if new_count >= self.max_functions_in_memory:
                message = f"Warning: Large codebase detected. {new_count} functions would exceed limit of {self.max_functions_in_memory}."
                logging.warning(message)
                
                if self.enforce_memory_limit:
                    logging.warning(f"Memory limit enforcement enabled. Rejecting {len(functions)} functions.")
                    if hasattr(self, '_analysis_stats'):
                        self._analysis_stats['rejected_functions'] += len(functions)
                    return
                else:
                    logging.warning("Consider using smaller codebases, increasing the limit, or enabling --enforce-memory-limit.")
            
            for func in functions:
                q = func.name
                self.func_by_qname[q] = func

                parts = q.split('.')
                if len(parts) >= 3:
                    module, cls = '.'.join(parts[:-2]), parts[-2]
                elif len(parts) >= 2:
                    module, cls = '.'.join(parts[:-1]), None
                else:
                    module, cls = '', None

                self.module_of[q] = module
                self.class_of[q] = cls

                short = func.signature.split('(')[0] if func.signature else parts[-1]
                self.short_index[short].add(q)
                
                mod = self.module_of[q]
                self.module_aliases.setdefault(mod, {}).update(func.source_aliases)
            
            if hasattr(self, '_analysis_stats'):
                self._analysis_stats['parsed_functions'] = len(self.func_by_qname)

    def find_function_dependencies(self, function_name: str, organize_by_levels: bool = False, lazy_mode: bool = False) -> Dict[str, Any]:
        """Find all dependencies for a function in correct order, optionally organized by levels"""
        start = function_name
        if start not in self.func_by_qname:
            bucket = self.short_index.get(function_name, set())
            if len(bucket) == 1:
                start = next(iter(bucket))
            elif not lazy_mode: # Only show ambiguity if not in lazy mode (where we expect things not to be found yet)
                candidates = []
                if bucket:
                    candidates = list(sorted(bucket))[:5]
                    sample = ', '.join(candidates)
                    logging.warning(f"Function '{function_name}' ambiguous. Candidates: {sample}...")
                else:
                    logging.warning(f"Function '{function_name}' not found.")
                return {'error': 'Function not found or is ambiguous.', 'candidates': list(bucket)}

        resolved_edges: Dict[str, Set[str]] = defaultdict(set)
        visited = {start}
        queue = deque([(start, 0)])
        all_raw_shortnames = set()
        external_dependencies = set()
        dependencies_by_level = {} if organize_by_levels else None

        while queue:
            cur, level = queue.popleft()
            
            # LAZY LOADING LOGIC
            if lazy_mode and cur not in self.func_by_qname:
                module_to_parse = self._qname_to_module(cur)
                if module_to_parse and module_to_parse not in self.parsed_modules:
                    file_to_parse = self._module_to_file(module_to_parse)
                    if file_to_parse:
                        logging.info(f"[Lazy] Parsing module: {module_to_parse}")
                        new_functions = self.analyze_file(file_to_parse)
                        self._store_functions(new_functions)
                        self.parsed_modules.add(module_to_parse)
                    else:
                        logging.warning(f"[Lazy] Could not find file for module: {module_to_parse}")

            finfo = self.func_by_qname.get(cur)
            if not finfo:
                continue

            if organize_by_levels and cur != start:
                dependencies_by_level.setdefault(level, set()).add(cur)

            for dep in finfo.dependencies:
                short = dep.short_name
                all_raw_shortnames.add(short)

                tgt = self._resolve_dependency(cur, dep)
                if tgt and self._is_internal(tgt):
                    resolved_edges[cur].add(tgt)
                    if tgt not in visited:
                        visited.add(tgt)
                        queue.append((tgt, level+1))
                else:
                    external_tgt = self._resolve_external_dependency(cur, dep)
                    if external_tgt:
                        external_dependencies.add(external_tgt)
                        if organize_by_levels:
                            dependencies_by_level.setdefault(level+1, set()).add(external_tgt)

        resolved_edges = {u: {v for v in vs if v in visited} for u, vs in resolved_edges.items()}
        ordered = self._topological_sort_resolved(visited, resolved_edges)
        
        # Remove the starting function itself from the final dependency list
        if ordered and ordered[0] == start:
            ordered.pop(0)

        # Update dependency levels to remove the start node if present
        if organize_by_levels and dependencies_by_level:
            if 1 in dependencies_by_level:
                dependencies_by_level[1].discard(start)

        return {
            'user_defined_order': ordered,
            'all_dependencies': all_raw_shortnames,
            'total_calls': len(all_raw_shortnames),
            'external_dependencies': sorted(external_dependencies),
            'dependencies_by_level': dependencies_by_level
        }

    def _get_nested_dependency_levels(self, function_name: str) -> Dict[int, Set[str]]:
        """Get the nested dependency levels for a specific function"""
        if function_name not in self.func_by_qname:
            return {}
        
        direct_deps = self.func_by_qname[function_name].dependencies
        resolved_internal = []
        resolved_external = []
        
        for d in direct_deps:
            internal_r = self._resolve_dependency(function_name, d)
            if internal_r:
                resolved_internal.append(internal_r)
            else:
                external_r = self._resolve_external_dependency(function_name, d)
                if external_r:
                    resolved_external.append(external_r)

        user_defined_direct_deps = {r for r in resolved_internal if r != function_name and r in self.func_by_qname}
        external_direct_deps = set(resolved_external)
        
        if not user_defined_direct_deps and not external_direct_deps:
            return {}
        
        nested_levels = {}
        
        level_2_deps = user_defined_direct_deps.union(external_direct_deps)
        if level_2_deps:
            nested_levels[2] = level_2_deps
        
        current_level_deps = user_defined_direct_deps
        visited_deps = {function_name} | level_2_deps
        level = 3
        
        while current_level_deps and level <= 6:
            next_level_deps = set()
            
            for dep in current_level_deps:
                if dep in self.func_by_qname:
                    dep_dependencies = self.func_by_qname[dep].dependencies
                    resolved_deps = set()
                    for d in dep_dependencies:
                        r = self._resolve_dependency(dep, d)
                        if not r:
                            r = self._resolve_external_dependency(dep, d)
                        if r and r != dep:
                            resolved_deps.add(r)
                    
                    all_new_deps = {d for d in resolved_deps if d not in visited_deps}
                    next_level_deps.update(all_new_deps)
                    visited_deps.update(all_new_deps)
            
            if next_level_deps:
                nested_levels[level] = next_level_deps
                current_level_deps = {d for d in next_level_deps if d in self.func_by_qname}
            else:
                break
            
            level += 1
        
        return nested_levels

    def _get_external_function_info(self, qname: str) -> Optional[Dict[str, Any]]:
        """Get basic information about external/standard library functions"""
        external_functions = {
            'secrets.randbelow': {'signature': 'randbelow(exclusive_upper_bound)', 'file': 'secrets.py (stdlib)', 'line': '25'},
            'random.randint': {'signature': 'randint(a, b)', 'file': 'random.py (stdlib)', 'line': '218'},
            'json.loads': {'signature': 'loads(s, **kwargs)', 'file': 'json/__init__.py (stdlib)', 'line': '346'},
            'os.path.exists': {'signature': 'exists(path)', 'file': 'posixpath.py (stdlib)', 'line': '18'}
        }
        
        if qname in external_functions:
            return external_functions[qname]
        
        parts = qname.split('.')
        if len(parts) >= 2:
            module, func = parts[0], parts[-1]
            if module in STDLIB_MODULES:
                return {
                    'signature': f'{func}(...)',
                    'file': f'{module} (Python standard library)',
                    'line': 'N/A'
                }
        
        return None

    def _resolve_dependency(self, caller_qname: str, dep: DependencyInfo) -> Optional[str]:
        """Resolves a dependency to a qualified function name in the codebase."""
        short, scope, owner = dep.short_name, dep.scope_tag, dep.owner
        caller_mod = self.module_of.get(caller_qname, '')
        caller_cls = self.class_of.get(caller_qname)

        if scope == 'CLASS_LOCAL' and caller_cls:
            cand = f"{caller_mod}.{caller_cls}.{short}"
            if cand in self.func_by_qname:
                return cand

        cand = f"{caller_mod}.{short}"
        if cand in self.func_by_qname:
            return cand
        
        if scope in ('UNSCOPED', 'OBJ'):
            aliases = self.module_aliases.get(caller_mod, {})
            if scope == 'UNSCOPED' and short in aliases:
                target = aliases[short]
                if target in self.func_by_qname and self._is_internal(target):
                    return target
            elif scope == 'OBJ' and owner in aliases:
                target_mod = aliases[owner]
                cand = f"{target_mod}.{short}"
                if cand in self.func_by_qname and self._is_internal(cand):
                    return cand
                    
        if scope == 'OBJ' and owner and caller_cls and owner == caller_cls:
            cand = f"{caller_mod}.{caller_cls}.{short}"
            if cand in self.func_by_qname:
                return cand

        bucket = self.short_index.get(short, set())
        if len(bucket) == 1:
            return next(iter(bucket))

        if scope == 'UNSCOPED':
            if short in aliases:
                target = aliases[short]
                init_targets = self._try_constructor_resolution(target)
                if len(init_targets) == 1:
                    return init_targets[0]
            
            class_pattern = f"{caller_mod}.{short}"
            init_candidate = f"{class_pattern}.__init__"
            if init_candidate in self.func_by_qname and self._is_internal(init_candidate):
                return init_candidate

        return None

    def _resolve_external_dependency(self, caller_qname: str, dep: DependencyInfo) -> Optional[str]:
        """Resolve external/stdlib dependencies that aren't in the codebase"""
        short, scope, owner = dep.short_name, dep.scope_tag, dep.owner
        
        if short in BUILTIN_METHODS or (scope == 'OBJ' and owner in ['self', 'cls']):
            return None
        
        finfo = self.func_by_qname.get(caller_qname)
        if not finfo:
            return None
            
        imports = finfo.imports
        aliases = self.module_aliases.get(self.module_of.get(caller_qname, ''), {})
        
        for module, functions in STDLIB_MODULES.items():
            if short in functions:
                for imp in imports:
                    if imp == module or imp.startswith(f"{module}."):
                        return f"{module}.{short}"
        
        if scope == 'UNSCOPED' and short in aliases:
            target = aliases[short]
            if not any(target.startswith(prefix) for prefix in self.project_prefixes):
                return target
                
        if scope == 'OBJ' and owner in aliases:
            target_mod = aliases[owner]
            if not any(target_mod.startswith(prefix) for prefix in self.project_prefixes):
                return f"{target_mod}.{short}"
        
        if scope == 'OBJ' and owner:
            for imp in imports:
                potential_qname = f"{imp}.{owner}.{short}"
                if potential_qname in STDLIB_SUBMODULES:
                    return potential_qname

        return None

    def _try_constructor_resolution(self, target: str) -> List[str]:
        """Try to resolve constructor calls for class instantiation"""
        init_target = f"{target}.__init__"
        if init_target in self.func_by_qname and self._is_internal(init_target):
            return [init_target]
        return []

    def _topological_sort_resolved(self, nodes: Set[str], edges: Dict[str, Set[str]]) -> List[str]:
        """Sort functions in dependency order using resolved edges"""
        in_deg = {n: 0 for n in nodes}
        for u in nodes:
            for v in edges.get(u, ()):
                if v in in_deg:
                    in_deg[v] += 1
        q = deque([n for n, d in in_deg.items() if d == 0])
        out = []
        while q:
            u = q.popleft()
            out.append(u)
            for v in edges.get(u, ()):
                in_deg[v] -= 1
                if in_deg[v] == 0:
                    q.append(v)
        if len(out) < len(nodes):
            cyc = [n for n, d in in_deg.items() if d > 0]
            cyc_count = len(cyc)
            cyc_sample = cyc[:5]
            logging.warning(f"{cyc_count} function(s) in cycle(s): {cyc_sample}{'...' if cyc_count > 5 else ''}")
            
        return out
    
    def _qname_to_module(self, qname: str) -> Optional[str]:
        """Converts a qualified function/method name to its module path."""
        # Handle direct function names (no dots)
        if '.' not in qname:
            # Search through discovered modules for this function
            for module_name in self._discovered_modules:
                if self._is_likely_containing_module(module_name, qname):
                    return module_name
            
            # If not found in discovered modules, try heuristic matching
            possible_names = [
                qname.lower(),
                qname.replace('_', '').lower(),
                qname.split('_')[0].lower() if '_' in qname else qname.lower()
            ]
            
            for module_name in self._discovered_modules:
                module_base = module_name.split('.')[-1].lower()
                if any(possible in module_base for possible in possible_names):
                    return module_name
                    
            return None
        
        parts = qname.split('.')
        # Heuristic: if it looks like Class.method, module is everything before the class
        if len(parts) >= 2 and parts[-2][0].isupper():
            return ".".join(parts[:-2])
        # Heuristic: if it looks like module.function, module is everything before the function
        elif len(parts) >= 2:
            return ".".join(parts[:-1])
        return None

    def _is_likely_containing_module(self, module_name: str, function_name: str) -> bool:
        """Check if a module is likely to contain the given function"""
        module_base = module_name.split('.')[-1].lower()
        func_lower = function_name.lower()
        
        # Direct name match
        if func_lower in module_base or module_base in func_lower:
            return True
            
        # Check for common patterns
        if '_' in function_name:
            func_parts = function_name.lower().split('_')
            if any(part in module_base for part in func_parts):
                return True
                
        return False

    def _module_to_file(self, module: str) -> Optional[str]:
        """Converts a module name (e.g., 'pkg.utils') to a file path relative to the root."""
        path_parts = module.split('.')
        
        # Try as a .py file first
        file_path = Path(*path_parts).with_suffix('.py')
        if (self.root_dir / file_path).exists():
            return str(file_path)
            
        # Try as a package with __init__.py
        init_path = Path(*path_parts) / '__init__.py'
        if (self.root_dir / init_path).exists():
            return str(init_path)
            
        return None

class _CallFinder(ast.NodeVisitor):
    """Find function calls within a function"""
    def __init__(self):
        self.calls = set()

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            self.calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                method_name, obj_name = node.func.attr, node.func.value.id
                if method_name not in BUILTIN_METHODS:
                    self.calls.add(f"{obj_name}.{method_name}")
            else:
                method_name = node.func.attr
                if method_name not in BUILTIN_ATTRS:
                    self.calls.add(method_name)
                    
        self.generic_visit(node)


class _ImportFinder(ast.NodeVisitor):
    """Find imports within a function or scope"""
    def __init__(self):
        self.imports = set()
        self.aliases = {}
        self.file_path = None

    def visit_Import(self, node):
        for alias in node.names:
            fq = alias.name
            local = alias.asname or alias.name.split('.')[-1]
            self.aliases[local] = fq
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        base = node.module or ""
        for alias in node.names:
            if alias.name == '*':
                logging.warning(f"Wildcard import `from {base} import *` in {self.file_path}. Resolution may be incomplete.")
                continue
            
            local = alias.asname or alias.name
            target = f"{base}.{alias.name}" if base else alias.name
            self.aliases[local] = target
            self.imports.add(target)
        self.generic_visit(node)


class _PythonASTAnalyzer(ast.NodeVisitor):
    """AST visitor for analyzing Python function dependencies"""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.source_lines = source.splitlines()
        self.functions: List[FunctionInfo] = []
        self.current_class = None
        
        import_finder = _ImportFinder()
        import_finder.file_path = file_path
        import_finder.visit(ast.parse(source))
        self.imports = import_finder.imports
        self.local_aliases = import_finder.aliases

    def visit_FunctionDef(self, node):
        func_info = self._extract_function_info(node)
        self.functions.append(func_info)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        func_info = self._extract_function_info(node)
        self.functions.append(func_info)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def _extract_function_info(self, node) -> FunctionInfo:
        """Extract function information from AST node"""
        func_name = node.name
        p = Path(self.file_path)
        if p.name == '__init__.py':
            mod = str(p.parent).replace(os.sep, '.')
        else:
            mod = str(p.with_suffix('')).replace(os.sep, '.')
        if self.current_class:
            full_func_name = f"{mod}.{self.current_class}.{func_name}"
        else:
            full_func_name = f"{mod}.{func_name}"

        start_line = node.lineno
        end_line = getattr(node, 'end_lineno', start_line)
        source_code = '\n'.join(self.source_lines[start_line-1:end_line])

        signature = self._get_function_signature(node)
        docstring = ast.get_docstring(node) or ""
        
        is_static = any(isinstance(d, ast.Name) and d.id == 'staticmethod' for d in node.decorator_list)
        is_class = any(isinstance(d, ast.Name) and d.id == 'classmethod' for d in node.decorator_list)
        func_kind = 'static' if is_static else ('class' if is_class else 'inst')

        call_finder = _CallFinder()
        call_finder.visit(node)
        
        import_finder = _ImportFinder()
        import_finder.visit(node)

        all_imports = self.imports.copy()
        all_imports.update(import_finder.imports)
        
        all_aliases = self.local_aliases.copy()
        all_aliases.update(import_finder.aliases)

        normalized: Set[DependencyInfo] = set()
        for c in call_finder.calls:
            if c.startswith('self.') or c.startswith('cls.'):
                normalized.add(DependencyInfo(c.split('.', 1)[1], 'CLASS_LOCAL'))
            elif '.' in c:
                owner, meth = c.split('.', 1)
                normalized.add(DependencyInfo(meth, 'OBJ', owner))
            else:
                normalized.add(DependencyInfo(c, 'UNSCOPED'))

        noisy = {'__call__'}
        normalized = {d for d in normalized if d.short_name not in noisy and not (d.short_name.startswith('__') and d.short_name.endswith('__'))}

        return FunctionInfo(
            name=full_func_name,
            file_path=self.file_path,
            line_number=start_line,
            source_code=source_code,
            dependencies=normalized,
            calls=set(d.short_name for d in normalized),
            imports=all_imports,
            signature=signature,
            docstring=docstring,
            source_aliases=all_aliases,
            kind=func_kind
        )

    def _get_function_signature(self, node) -> str:
        """Get function signature as string"""
        args = [arg.arg for arg in node.args.args]
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            args.append(f"**{node.args.kwarg.arg}")
        return f"{node.name}({', '.join(args)})"


class CodebaseExtractor:
    """Extract and manage codebase archives"""
    def __init__(self, temp_dir: Optional[str] = None):
        self.temp_dir = temp_dir or tempfile.mkdtemp()
        self.extracted_path: Optional[Path] = None

    def extract_archive(self, archive_path: str) -> str:
        """Extract .zip or .whl file and return extraction path"""
        archive_path = Path(archive_path)
        
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
            
        extract_dir = Path(self.temp_dir) / f"extracted_{int(time.time())}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        if archive_path.suffix.lower() == '.whl' and not WHEEL_SUPPORT:
            logging.warning("wheel package not available, treating as zip file")
            
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            self.extracted_path = extract_dir
            return str(extract_dir)
            
        except zipfile.BadZipFile:
            raise ValueError(f"Invalid or corrupted archive: {archive_path}")
            
    def cleanup(self):
        """Clean up temporary files"""
        if self.extracted_path and self.extracted_path.exists():
            shutil.rmtree(self.extracted_path)


class AnalysisRunner:
    """Main application class"""
    def __init__(self, codebase_path: str, function_snippet_file: str, lazy_mode: bool = False):
        self.codebase_path = codebase_path
        self.function_snippet_file = function_snippet_file
        self.lazy_mode = lazy_mode
        self.extractor = CodebaseExtractor()
        self.extracted_dir: Optional[str] = None

    def run(self) -> Dict[str, Any]:
        """Run the complete analysis"""
        keep = bool(os.environ.get("CDA_KEEP_EXTRACTED"))
        start_time = time.time()
        try:
            logging.info(f"Extracting codebase from {self.codebase_path}...")
            extract_start = time.time()
            self.extracted_dir = self.extractor.extract_archive(self.codebase_path)
            extract_time = time.time() - extract_start
            logging.info(f"Extracted to: {self.extracted_dir} ({extract_time:.2f}s)")
            
            with open(self.function_snippet_file, 'r', encoding='utf-8') as f:
                function_snippet = f.read().strip()
            
            logging.info("Searching for function in codebase...")
            search_start = time.time()
            search_result = self._find_function_in_codebase(function_snippet)
            search_time = time.time() - search_start
            
            if not search_result:
                total_time = time.time() - start_time
                return {
                    'error': 'Function not found in codebase',
                    'function_snippet': function_snippet,
                    'timing': {'total_time': total_time, 'extract_time': extract_time, 'search_time': search_time}
                }
                
            logging.info("Analyzing function dependencies...")
            analysis_start = time.time()
            dependency_result = self._analyze_dependencies(search_result)
            analysis_time = time.time() - analysis_start
            
            total_time = time.time() - start_time
            
            return {
                'success': True,
                'function_found': search_result,
                'dependencies': dependency_result,
                'analyzer': dependency_result.get('analyzer'),
                'codebase_path': self.codebase_path,
                'extracted_to': self.extracted_dir if keep else None,
                'timing': {'total_time': total_time, 'extract_time': extract_time, 'search_time': search_time, 'analysis_time': analysis_time}
            }
            
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            total_time = time.time() - start_time
            return {'error': str(e), 'codebase_path': self.codebase_path, 'timing': {'total_time': total_time}}
        finally:
            if not keep:
                self.extractor.cleanup()

    def _find_function_in_codebase(self, function_snippet: str) -> Optional[Dict[str, Any]]:
        """Find the function in the extracted codebase"""
        function_name = self._extract_function_name(function_snippet)
        
        if not function_name:
            return None # Simplified: if we can't get a name, we can't proceed

        if '.' in function_name and function_name.count('.') >= 1:
            return {'function_name': function_name, 'search_method': 'qualified_name', 'file_path': 'N/A', 'line_number': 0}

        content_search = ContentSearchEngine(self.extracted_dir)
        search_pattern = f"def\\s+{function_name}\\s*\\("
        search_result = content_search.search_content(search_pattern, file_patterns=['*.py'], is_regex=True, max_results=5)
        
        if search_result.matches:
            best_match = search_result.matches[0]
            return {'function_name': function_name, 'search_method': 'definition_match', 'file_path': best_match.file_path, 'line_number': best_match.line_number}
            
        return None

    def _extract_function_name(self, snippet: str) -> Optional[str]:
        """Extract function name from code snippet"""
        stripped = snippet.strip()
        if '.' in stripped and not any(k in stripped for k in ['def ', 'class ', 'import ']):
            clean_name = stripped.split('(')[0].strip()
            if clean_name.replace('.', '_').replace('_', '').isalnum():
                return clean_name
        
        try:
            tree = ast.parse(snippet)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node.name
        except SyntaxError:
            pass
            
        match = re.search(r'def\s+(\w+)\s*\(', snippet)
        if match:
            return match.group(1)
            
        if stripped and stripped.replace('.', '_').replace('_', '').isalnum():
            return stripped
                
        return None

    def _analyze_dependencies(self, function_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze function dependencies"""
        analyzer = PythonDependencyAnalyzer(self.extracted_dir)
        function_name = function_info['function_name']

        if self.lazy_mode:
            analyzer.analyze_on_demand(function_name)
            
            # If we have file path info from search, try to load that specific file
            if function_info.get('file_path') and function_info['file_path'] != 'N/A':
                file_path = function_info['file_path']
                logging.info(f"[Lazy] Loading target function file: {file_path}")
                target_functions = analyzer.analyze_file(file_path)
                analyzer._store_functions(target_functions)
        else:
            analyzer.analyze_codebase()
        
        # In lazy mode, the initial function might still not be found if the file doesn't exist
        if function_name not in analyzer.func_by_qname and function_name not in analyzer.short_index:
             return {'error': f'Function {function_name} not found in codebase.', 'analyzer': analyzer}

        dependencies_result = analyzer.find_function_dependencies(function_name, organize_by_levels=True, lazy_mode=self.lazy_mode)
        
        dependencies_result['analyzer'] = analyzer
        
        return dependencies_result


def main():
    """Main entry point"""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    parser = argparse.ArgumentParser(
        description='Analyze Python codebase dependencies from function snippet',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python codebase_dependency_analyzer.py mypackage.whl function_snippet.txt
  python codebase_dependency_analyzer.py codebase.zip snippet.py --lazy
        """
    )
    
    parser.add_argument('codebase', help='Path to .whl or .zip file containing the codebase')
    parser.add_argument('snippet', help='Path to text file containing function snippet')
    parser.add_argument('--output', '-o', help='Output file for results (default: stdout)')
    parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format (default: text)')
    parser.add_argument('--lazy', action='store_true', help='Enable lazy analysis mode for faster targeted scans')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.codebase):
        logging.error(f"Codebase file not found: {args.codebase}")
        return 1
        
    if not os.path.exists(args.snippet):
        logging.error(f"Function snippet file not found: {args.snippet}")
        return 1
    
    codebase_ext = Path(args.codebase).suffix.lower()
    if codebase_ext not in ['.zip', '.whl']:
        logging.error(f"Unsupported codebase file type: {codebase_ext}. Expected .zip or .whl")
        return 1
        
    runner = AnalysisRunner(args.codebase, args.snippet, lazy_mode=args.lazy)
    result = runner.run()
    
    if args.format == 'json':
        # Custom serializer to handle dataclasses and sets
        class CustomEncoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, (set, deque)):
                    return list(o)
                if hasattr(o, '__dict__'):
                    return o.__dict__
                return super().default(o)
        output = json.dumps(result, indent=2, cls=CustomEncoder)
    else:
        output = _format_text_output(result)
        
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Results written to: {args.output}")
    else:
        try:
            print(output)
        except UnicodeEncodeError:
            ascii_safe_output = output.encode('ascii', errors='replace').decode('ascii')
            print(ascii_safe_output)
            
    return 0 if result.get('success') else 1


def _format_text_output(result: Dict[str, Any]) -> str:
    """Format result as human-readable text with level-based dependency organization"""
    if 'error' in result:
        return f"Error: {result['error']}"
        
    deps = result.get('dependencies', {})
    if deps.get('error'):
        if 'candidates' in deps and deps['candidates']:
             output = ["Codebase Dependency Analysis Results", "=" * 40, ""]
             output.append("⚠️  Function name is ambiguous!")
             output.append("Available candidates:")
             for i, cand in enumerate(deps['candidates'][:10], 1):
                 output.append(f"  {i}. {cand}")
             output.append("\nPlease specify the fully qualified name (e.g., test.models.UserRepository.save)")
             return "\n".join(output)
        else:
             return f"Error: {deps['error']}"
        
    output = ["Codebase Dependency Analysis Results", "=" * 40, ""]
    
    func_info = result['function_found']
    output.append(f"Function found: {func_info['function_name']}")
    output.append(f"File: {func_info['file_path']}")
    output.append(f"Line: {func_info['line_number']}")
    
    timing = result.get('timing', {})
    if timing:
        output.extend(["", "Performance Metrics:", "-" * 20,
                       f"Total Time: {timing.get('total_time', 0):.2f}s",
                       f"Extraction Time: {timing.get('extract_time', 0):.2f}s",
                       f"Search Time: {timing.get('search_time', 0):.2f}s",
                       f"Analysis Time: {timing.get('analysis_time', 0):.2f}s"])
    
    output.append("")
    
    dependencies_by_level = deps.get('dependencies_by_level', {})
    if dependencies_by_level:
        total_deps = sum(len(dep_set) for dep_set in dependencies_by_level.values())
        output.extend(["Dependencies by Level:", "=" * 25, f"Total Dependencies: {total_deps}", ""])
        
        for level in sorted(dependencies_by_level.keys()):
            level_deps = sorted(dependencies_by_level[level])
            if not level_deps: continue
            
            level_name = "Direct Dependencies" if level == 1 else f"Level-{level} Dependencies"
            output.append(f"{level_name} ({len(level_deps)} functions):")
            output.append("-" * (len(level_name) + 20))
            
            for i, dep_name in enumerate(level_deps, 1):
                output.append(f"  {i}. {dep_name}")
            output.append("")
    else:
        all_deps = deps.get('user_defined_order', [])
        if all_deps:
            output.extend([f"Dependencies ({len(all_deps)} total):", "-" * 30])
            for i, dep_name in enumerate(all_deps, 1):
                output.append(f"{i}. {dep_name}")
            output.append("")

    analyzer = result.get('analyzer')
    if not analyzer:
        return "\n".join(output)
        
    output.extend(["", "Detailed Dependency Information:", "=" * 35])
    
    all_dependencies_in_order = deps.get('user_defined_order', [])
    for i, dep_name in enumerate(all_dependencies_in_order, 1):
        output.append(f"\n{i}. {dep_name}")
        output.append("=" * (len(dep_name) + 4))
        
        if dep_name in analyzer.func_by_qname:
            func_details = analyzer.func_by_qname[dep_name]
            output.append(f"File: {func_details.file_path}")
            output.append(f"Line: {func_details.line_number}")
            output.append(f"Signature: {func_details.signature}")
            if func_details.docstring:
                output.append(f"Docstring: {func_details.docstring[:100]}...")

            nested_deps = analyzer._get_nested_dependency_levels(dep_name)
            if nested_deps:
                output.append("\n  Nested Dependencies:")
                for nested_level, nested_funcs in sorted(nested_deps.items()):
                    if nested_funcs:
                        output.append(f"    Level-{nested_level}: {', '.join(sorted(nested_funcs))}")

            output.append("\n  Source Code:")
            output.append("-" * 60)
            for line_num, line in enumerate(func_details.source_code.splitlines(), func_details.line_number):
                output.append(f"  {line_num:4d}: {line}")
            output.append("-" * 60)
        else:
            external_info = analyzer._get_external_function_info(dep_name)
            if external_info:
                output.append(f"File: {external_info['file']}")
                output.append(f"Signature: {external_info['signature']}")
            else:
                output.append("(External or unresolved dependency - details not available)")
                
    return "\n".join(output)


if __name__ == '__main__':
    sys.exit(main())