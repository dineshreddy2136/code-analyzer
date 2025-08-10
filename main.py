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

Usage:
    python codebase_dependency_analyzer.py <codebase.zip> <function_snippet.txt>
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
from typing import Dict, List, Set, Optional, Tuple, Any, Union
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


@dataclass
class DependencyInfo:
    """Represents a function dependency"""
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
    dependencies: Set[Tuple[str, str, Optional[str]]] = field(default_factory=set)  # (shortname, scope_tag, owner)
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
        self.functions: Dict[str, FunctionInfo] = {}
        self.max_functions_in_memory = max_functions_in_memory
        self.enforce_memory_limit = enforce_memory_limit
        self._lock = threading.Lock()  # For thread safety
        self.func_by_qname: Dict[str, FunctionInfo] = {}
        self.short_index: Dict[str, Set[str]] = defaultdict(set)   # 'save' -> {'pkg.mod.Class.save', ...}
        self.module_of: Dict[str, str] = {}                        # qname -> 'pkg.mod'
        self.class_of: Dict[str, Optional[str]] = {}               # qname -> class or None
        self.project_prefixes: Set[str] = set()                    # internal top-level packages
        self.module_aliases: Dict[str, Dict[str, str]] = defaultdict(dict)  # 'pkg.mod' -> {'bar': 'pkg.utils.foo'}
        
    def analyze_file(self, file_path: str) -> List[FunctionInfo]:
        """Analyze a Python file and extract function information"""
        file_path_obj = Path(file_path)
        
        # Handle both absolute and relative paths
        if file_path_obj.is_absolute():
            full_path = file_path_obj
            # Calculate relative path from root_dir for module naming
            try:
                relative_path = str(full_path.relative_to(self.root_dir))
            except ValueError:
                # If file is not under root_dir, use the filename
                relative_path = full_path.name
        else:
            full_path = self.root_dir / file_path
            relative_path = file_path
        
        try:
            # Check file size to avoid loading extremely large files
            file_stats = full_path.stat()
            max_file_size = MAX_FILE_SIZE_MB * 1024 * 1024  # Use constant
            if file_stats.st_size > max_file_size:
                logging.warning(f"Skipping large file {relative_path} ({file_stats.st_size / (1024*1024):.1f}MB)")
                return []
                
            with open(full_path, 'r', encoding='utf-8') as f:
                source = f.read()
                
            tree = ast.parse(source)
            analyzer = _PythonASTAnalyzer(relative_path, source)
            analyzer.visit(tree)
            
            # Store functions in the analyzer's data structures (same as analyze_codebase)
            functions = analyzer.functions
            for func in functions:
                q = func.name  # qualified name
                self.functions[q] = func  # keep legacy map working
                self.func_by_qname[q] = func
                
                # Update stats
                if hasattr(self, '_analysis_stats'):
                    self._analysis_stats['parsed_functions'] += 1
                else:
                    self._analysis_stats = {'parsed_functions': 1}
            
            return functions
            
        except (SyntaxError, UnicodeDecodeError, FileNotFoundError, OSError) as e:
            logging.warning(f"Could not parse {file_path}: {e}")
            # Update stats for skipped files
            if hasattr(self, '_analysis_stats'):
                self._analysis_stats['skipped_files'] += 1
            return []
            
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
        
        # Track analysis statistics
        self._analysis_stats = {
            'total_files': len(python_files),
            'skipped_files': 0,
            'rejected_functions': 0,  # Track function rejections separately
            'parsed_functions': 0,
            'analysis_start_time': time.time()
        }
        
        # Use parallel processing for large codebases
        if len(python_files) > 10:
            self._analyze_files_parallel(python_files)
        else:
            self._analyze_files_sequential(python_files)
            
        # Mark internal packages (so stdlib/Django don't leak in)
        SKIP_TOPS = {'__pycache__'}
        def _is_meta_dir(name: str) -> bool:
            return name.endswith(('.dist-info', '.data', '.egg-info'))
            
        prefixes = set()
        for root, _, files in os.walk(self.root_dir):
            for f in files:
                if f.endswith('.py'):
                    rel_dir = Path(root).relative_to(self.root_dir)
                    if rel_dir.parts:  # Only process files in subdirectories
                        top = rel_dir.parts[0]
                        # Accept any directory containing Python files, but prefer packages with __init__.py
                        if top not in SKIP_TOPS and not _is_meta_dir(top):
                            prefixes.add(top)
        self.project_prefixes = prefixes
        print(f"Project prefixes (internal): {sorted(self.project_prefixes)}")
        
        # Print analysis summary
        analysis_time = time.time() - self._analysis_stats['analysis_start_time']
        logging.info(f"Analysis complete: {self._analysis_stats['parsed_functions']} functions parsed in {analysis_time:.2f}s")
        if self._analysis_stats['skipped_files'] > 0:
            print(f"Skipped {self._analysis_stats['skipped_files']} files due to size/parse errors")
        if self._analysis_stats.get('rejected_functions', 0) > 0:
            print(f"Rejected {self._analysis_stats['rejected_functions']} functions due to memory limits")
        
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
        max_workers = min(DEFAULT_MAX_WORKERS, len(python_files))  # Use constant
        total_files = len(python_files)
        processed_files = 0
        
        print(f"Using {max_workers} parallel workers for analysis...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all file analysis tasks
            future_to_file = {
                executor.submit(self.analyze_file, file_path): file_path 
                for file_path in python_files
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    functions = future.result()
                    self._store_functions(functions)
                    processed_files += 1
                    
                    # Progress reporting for large codebases
                    if processed_files % 50 == 0 or processed_files == total_files:
                        progress = (processed_files / total_files) * 100
                        print(f"Progress: {processed_files}/{total_files} files analyzed ({progress:.1f}%)")
                        
                except Exception as e:
                    logging.warning(f"Error processing {file_path}: {e}")
                    processed_files += 1
                    
    def _store_functions(self, functions: List[FunctionInfo]) -> None:
        """Store function information thread-safely with memory management"""
        with self._lock:
            # Check memory limits
            current_count = len(self.functions)
            new_count = current_count + len(functions)
            
            if new_count >= self.max_functions_in_memory:
                message = f"Warning: Large codebase detected. {new_count} functions would exceed limit of {self.max_functions_in_memory}."
                print(message)
                
                if self.enforce_memory_limit:
                    print(f"Memory limit enforcement enabled. Rejecting {len(functions)} functions to stay within limit.")
                    # Update stats for rejected functions - not files
                    if hasattr(self, '_analysis_stats'):
                        self._analysis_stats['rejected_functions'] += len(functions)
                    return
                else:
                    print("Consider using smaller codebases or increasing max_functions_in_memory, or enable enforce_memory_limit=True.")
                
            for func in functions:
                q = func.name                      # qualified
                self.functions[q] = func           # keep legacy map working
                self.func_by_qname[q] = func

                parts = q.split('.')
                if len(parts) >= 3:
                    module = '.'.join(parts[:-2]); cls = parts[-2]
                elif len(parts) >= 2:
                    module = '.'.join(parts[:-1]); cls = None
                else:
                    module, cls = '', None

                self.module_of[q] = module
                self.class_of[q] = cls

                short = func.signature.split('(')[0] if func.signature else parts[-1]
                self.short_index[short].add(q)
                
                # Store module-level aliases
                mod = self.module_of[q]
                self.module_aliases.setdefault(mod, {}).update(func.source_aliases)
                
            # Update stats
            if hasattr(self, '_analysis_stats'):
                self._analysis_stats['parsed_functions'] = len(self.functions)
                
    def find_function_dependencies(self, function_name: str, organize_by_levels: bool = False) -> Dict[str, Any]:
        """Find all dependencies for a function in correct order, optionally organized by levels"""
        # accept qualified or short; map short→unique if possible
        start = function_name
        if start not in self.func_by_qname:
            bucket = self.short_index.get(function_name, set())
            if len(bucket) == 1:
                start = next(iter(bucket))
            else:
                candidates = []
                if bucket:
                    candidates = list(sorted(bucket))[:5]
                    sample = ', '.join(candidates)
                    print(f"Function '{function_name}' ambiguous. Candidates: {sample}...")
                else:
                    print(f"Function '{function_name}' not found.")
                return {
                    'user_defined_order': [],
                    'all_dependencies': set(),
                    'total_calls': 0,
                    'external_dependencies': [],
                    'dependencies_by_level': {} if organize_by_levels else None,
                    'ambiguous_function': True,
                    'candidates': candidates
                }

        resolved_edges: Dict[str, Set[str]] = defaultdict(set)
        visited = {start}
        queue = deque([(start, 0)])  # Use deque for O(1) operations
        all_raw_shortnames = set()
        external_dependencies = set()
        dependencies_by_level = {} if organize_by_levels else None

        while queue:
            cur, level = queue.popleft()  # O(1) operation instead of list.pop(0)
            finfo = self.func_by_qname.get(cur)
            if not finfo:
                continue

            if organize_by_levels and level > 0:
                dependencies_by_level.setdefault(level, set()).add(cur)

            for dep in finfo.dependencies:  # (short, scope, owner)
                short = dep[0]
                all_raw_shortnames.add(short)

                tgt = self._resolve_dependency(cur, dep)
                if tgt and self._is_internal(tgt):
                    resolved_edges[cur].add(tgt)
                    if tgt not in visited:
                        visited.add(tgt)
                        queue.append((tgt, level+1))
                else:
                    # Try external resolution if internal resolution failed
                    external_tgt = self._resolve_external_dependency(cur, dep)
                    if external_tgt:
                        external_dependencies.add(external_tgt)
                        if organize_by_levels:
                            dependencies_by_level.setdefault(level+1, set()).add(external_tgt)

        # Ensure edges only include nodes present in visited set
        resolved_edges = {u: {v for v in vs if v in visited} for u, vs in resolved_edges.items()}
        ordered = self._topological_sort_resolved(visited, resolved_edges)
        if ordered and ordered[0] == start:
            ordered = ordered[1:]

        final_order = ordered + sorted(external_dependencies)
        out = {
            'user_defined_order': final_order,
            'all_dependencies': all_raw_shortnames,
            'total_calls': len(all_raw_shortnames),
            'external_dependencies': sorted(external_dependencies)
        }
        if organize_by_levels:
            out['dependencies_by_level'] = dependencies_by_level
        return out

    def _get_nested_dependency_levels(self, function_name: str, global_dependencies_by_level: Dict[int, Set[str]]) -> Dict[int, Set[str]]:
        """Get the nested dependency levels for a specific function"""
        if function_name not in self.func_by_qname:
            return {}
        
        # Get direct dependencies of this specific function
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
        
        # Build nested levels by tracing this function's specific dependency chain
        nested_levels = {}
        
        # Level 2: Direct dependencies of this function (both internal and external)
        level_2_deps = user_defined_direct_deps.union(external_direct_deps)
        if level_2_deps:
            nested_levels[2] = level_2_deps
        
        current_level_deps = user_defined_direct_deps
        visited_deps = set([function_name])  # Track visited to prevent cycles
        level = 3  # Start at level 3 for next level dependencies
        
        while current_level_deps and level <= 6:  # Limit depth to prevent infinite recursion
            next_level_deps = set()
            
            # For each dependency at current level, find its dependencies
            for dep in current_level_deps:
                if dep in self.func_by_qname and dep not in visited_deps:
                    visited_deps.add(dep)
                    dep_dependencies = self.func_by_qname[dep].dependencies
                    resolved_deps = set()
                    for d in dep_dependencies:
                        # Try both internal and external dependency resolution
                        r = self._resolve_dependency(dep, d)
                        if not r:
                            r = self._resolve_external_dependency(dep, d)
                        if r and r != dep:
                            resolved_deps.add(r)
                    
                    # Include both user-defined and external dependencies that haven't been visited
                    all_new_deps = {d for d in resolved_deps if d not in visited_deps}
                    next_level_deps.update(all_new_deps)
            
            if next_level_deps:
                nested_levels[level] = next_level_deps
                # Only continue with user-defined functions for further traversal
                current_level_deps = {d for d in next_level_deps if d in self.func_by_qname}
            else:
                break
                
            level += 1
        
        return nested_levels

    def _get_external_function_info(self, qname: str) -> Optional[Dict[str, Any]]:
        """Get basic information about external/standard library functions"""
        external_functions = {
            # secrets module
            'secrets.randbelow': {
                'signature': 'randbelow(exclusive_upper_bound)',
                'source': 'def randbelow(exclusive_upper_bound):\n    """Return a random int in the range [0, n)."""\n    if exclusive_upper_bound <= 0:\n        raise ValueError("Upper bound must be positive.")\n    return _sysrand._randbelow(exclusive_upper_bound)',
                'dependencies': ['_sysrand._randbelow', 'ValueError'],
                'file': 'secrets.py (Python standard library)',
                'line': '25'
            },
            'secrets.randbytes': {
                'signature': 'randbytes(n)',
                'source': 'def randbytes(n):\n    """Generate n random bytes."""\n    return _sysrand.randbytes(n)',
                'dependencies': ['_sysrand.randbytes'],
                'file': 'secrets.py (Python standard library)',
                'line': '30'
            },
            'secrets.token_bytes': {
                'signature': 'token_bytes(nbytes=None)',
                'source': 'def token_bytes(nbytes=None):\n    """Return a random byte string."""\n    if nbytes is None:\n        nbytes = DEFAULT_ENTROPY\n    return randbytes(nbytes)',
                'dependencies': ['randbytes', 'DEFAULT_ENTROPY'],
                'file': 'secrets.py (Python standard library)',
                'line': '35'
            },
            # random module  
            'random.randint': {
                'signature': 'randint(a, b)',
                'source': 'def randint(a, b):\n    """Return random integer in range [a, b], including both end points."""\n    return randrange(a, b+1)',
                'dependencies': ['randrange'],
                'file': 'random.py (Python standard library)',
                'line': '218'
            },
            'random.choice': {
                'signature': 'choice(seq)',
                'source': 'def choice(seq):\n    """Choose a random element from a non-empty sequence."""\n    return seq[randbelow(len(seq))]',
                'dependencies': ['randbelow', 'len'],
                'file': 'random.py (Python standard library)', 
                'line': '290'
            },
            # json module
            'json.loads': {
                'signature': 'loads(s, **kwargs)',
                'source': 'def loads(s, *, cls=None, object_hook=None, **kwargs):\n    """Deserialize JSON string to Python object."""\n    return _default_decoder.decode(s)',
                'dependencies': ['_default_decoder.decode'],
                'file': 'json/__init__.py (Python standard library)',
                'line': '346'
            },
            'json.dumps': {
                'signature': 'dumps(obj, **kwargs)',
                'source': 'def dumps(obj, *, skipkeys=False, ensure_ascii=True, **kwargs):\n    """Serialize Python object to JSON string."""\n    return _default_encoder.encode(obj)',
                'dependencies': ['_default_encoder.encode'],
                'file': 'json/__init__.py (Python standard library)',
                'line': '231'
            },
            # datetime module
            'datetime.now': {
                'signature': 'now(tz=None)',
                'source': 'def now(cls, tz=None):\n    """Return current local date and time."""\n    return cls.fromtimestamp(time.time(), tz)',
                'dependencies': ['fromtimestamp', 'time.time'],
                'file': 'datetime.py (Python standard library)',
                'line': '1470'
            },
            # os module
            'os.path.exists': {
                'signature': 'exists(path)',
                'source': 'def exists(path):\n    """Test whether a path exists."""\n    try:\n        st = os.stat(path)\n    except (OSError, ValueError):\n        return False\n    return True',
                'dependencies': ['os.stat', 'OSError', 'ValueError'],
                'file': 'posixpath.py (Python standard library)',
                'line': '18'
            }
        }
        
        # Try exact match first
        if qname in external_functions:
            return external_functions[qname]
            
        # Try to generate basic info for common patterns
        parts = qname.split('.')
        if len(parts) >= 2:
            module = parts[0]
            func = parts[-1]
            
            # Generate basic info for stdlib modules
            stdlib_modules = list(STDLIB_MODULES.keys())
            if module in stdlib_modules:
                return {
                    'signature': f'{func}(...)',
                    'source': f'# {qname} - Standard library function\n# Source not available in static analysis',
                    'dependencies': [],
                    'file': f'{module} (Python standard library)',
                    'line': 'N/A'
                }
        
        return None
        
    def _resolve_dependency(self, caller_qname: str, dep: Tuple[str, str, Optional[str]]) -> Optional[str]:
        """Resolves a dependency triple to a qualified function name in the codebase."""
        short, scope, owner = dep
        caller_mod = self.module_of.get(caller_qname, '')
        caller_cls = self.class_of.get(caller_qname)

        # 1) same class (for self./cls.)
        if scope == 'CLASS_LOCAL' and caller_cls:
            cand = f"{caller_mod}.{caller_cls}.{short}"
            if cand in self.func_by_qname:
                return cand

        # 2) same module top-level
        cand = f"{caller_mod}.{short}"
        if cand in self.func_by_qname:
            return cand
            
        # 3) Check for import aliases in UNSCOPED and OBJ calls
        if scope in ('UNSCOPED', 'OBJ'):
            aliases = self.module_aliases.get(caller_mod, {})
            # direct function import alias: from pkg.m import foo as bar -> bar()
            if scope == 'UNSCOPED' and short in aliases:
                target = aliases[short]
                # If target is relative, make it absolute by prepending the project prefix
                if not target.startswith(tuple(self.project_prefixes)):
                    # Try to make it absolute by finding which project prefix works
                    for prefix in self.project_prefixes:
                        abs_target = f"{prefix}.{target}"
                        if abs_target in self.func_by_qname and self._is_internal(abs_target):
                            return abs_target
                else:
                    # Target is already absolute
                    if target in self.func_by_qname and self._is_internal(target):
                        return target
            # module alias receiver: import pkg.m as u; u.foo()
            if scope == 'OBJ' and owner in aliases:
                target_mod = aliases[owner]         # 'pkg.m'
                # If target_mod is relative, make it absolute
                if not target_mod.startswith(tuple(self.project_prefixes)):
                    for prefix in self.project_prefixes:
                        abs_target_mod = f"{prefix}.{target_mod}"
                        cand = f"{abs_target_mod}.{short}"
                        if cand in self.func_by_qname and self._is_internal(cand):
                            return cand
                else:
                    # target_mod is already absolute
                    cand = f"{target_mod}.{short}"
                    if cand in self.func_by_qname and self._is_internal(cand):
                        return cand
                        
        # 4) Check for same-class static/classmethod calls (Class.method from within Class)
        if scope == 'OBJ' and owner and caller_cls and owner == caller_cls:
            cand = f"{caller_mod}.{caller_cls}.{short}"
            if cand in self.func_by_qname:
                return cand

        # 5) unique across project
        bucket = self.short_index.get(short, set())
        if len(bucket) == 1:
            return next(iter(bucket))

        # 6) Try constructor for class instantiation (e.g., UserService() -> UserService.__init__)
        # Handle both aliased and direct class calls
        if scope == 'UNSCOPED':
            # Check if it's an aliased class
            if short in aliases:
                target = aliases[short]
                init_targets = self._try_constructor_resolution(target)
                if len(init_targets) == 1:
                    return init_targets[0]
            
            # Also try direct class instantiation (MyClass() when MyClass is in same module)
            # Look for class.short pattern in same module
            class_pattern = f"{caller_mod}.{short}"
            init_candidate = f"{class_pattern}.__init__"
            if init_candidate in self.func_by_qname and self._is_internal(init_candidate):
                return init_candidate

        return None   # ambiguous → drop
    
    def _resolve_external_dependency(self, caller_qname: str, dep: Tuple[str, str, Optional[str]]) -> Optional[str]:
        """Resolve external/stdlib dependencies that aren't in the codebase"""
        short, scope, owner = dep
        caller_mod = self.module_of.get(caller_qname, '')
        
        # Skip builtin methods and common instance methods that shouldn't be tracked
        if short in BUILTIN_METHODS or (scope == 'OBJ' and owner in ['self', 'cls']):
            return None
        
        # Get function info to check imports
        finfo = self.func_by_qname.get(caller_qname)
        if not finfo:
            return None
            
        imports = finfo.imports
        aliases = self.module_aliases.get(caller_mod, {})
        
        # Common stdlib patterns
        stdlib_modules = STDLIB_MODULES
        
        # 1. Check if short name belongs to known stdlib modules
        for module, functions in stdlib_modules.items():
            if short in functions:
                # Check if this module is imported
                module_patterns = [module, f'{module}.*']
                for imp in imports:
                    if any(imp.startswith(pattern.replace('*', '')) for pattern in module_patterns):
                        return f"{module}.{short}"
        
        # 2. Check aliases for external modules
        if scope == 'UNSCOPED' and short in aliases:
            target = aliases[short]
            # If target doesn't start with project prefix, it's likely external
            if not any(target.startswith(prefix) for prefix in self.project_prefixes):
                return target
                
        # 3. Check module.function pattern for externals
        if scope == 'OBJ' and owner in aliases:
            target_mod = aliases[owner]
            if not any(target_mod.startswith(prefix) for prefix in self.project_prefixes):
                return f"{target_mod}.{short}"
        
        # 4. Direct module references and complex paths (e.g., os.path.exists)
        if scope == 'OBJ' and owner:
            # First, check if owner is a direct alias
            if owner in aliases:
                target_mod = aliases[owner]
                if not any(target_mod.startswith(prefix) for prefix in self.project_prefixes):
                    return f"{target_mod}.{short}"
            
            # Check if owner is a known stdlib module or submodule
            for module in stdlib_modules:
                if owner == module:
                    # Direct module reference: os.getcwd, json.loads, etc.
                    for imp in imports:
                        if imp == module or imp.startswith(f"{module}."):
                            return f"{owner}.{short}"
                elif owner.startswith(f"{module}."):
                    # Submodule reference: os.path.exists
                    for imp in imports:
                        if imp.startswith(module):
                            return f"{owner}.{short}"
            
            # Only try to reconstruct for known stdlib patterns, not builtin methods
            if owner not in ['self', 'cls'] and short not in BUILTIN_METHODS:
                for imp in imports:  # e.g., imp = 'os'
                    # Only for known stdlib modules
                    if imp in stdlib_modules:
                        potential_qname = f"{imp}.{owner}.{short}"  # e.g., "os.path.exists"
                        
                        # Check if this reconstructed name is a known external function
                        # BUT only if the owner looks like a known submodule, not a variable name
                        if (owner in ['path', 'environ', 'urlencode', 'parse', 'request', 'error', 'response'] and
                            (potential_qname in STDLIB_SUBMODULES or 
                             any(potential_qname.startswith(f"{mod}.") for mod in stdlib_modules))):
                            return potential_qname
            
            # Check for complex stdlib paths like urllib.parse.urlencode
            stdlib_submodules = STDLIB_SUBMODULES
            
            for submodule, functions in stdlib_submodules.items():
                if short in functions and (owner == submodule or owner in submodule):
                    # Check if base module is imported
                    base_module = submodule.split('.')[0]
                    for imp in imports:
                        if imp.startswith(base_module):
                            return f"{submodule}.{short}"
        
        return None
    
    def _try_constructor_resolution(self, target: str) -> List[str]:
        """Try to resolve constructor calls for class instantiation"""
        init_targets = []
        
        # Handle relative targets
        if not target.startswith(tuple(self.project_prefixes)):
            for prefix in self.project_prefixes:
                abs_target = f"{prefix}.{target}.__init__"
                if abs_target in self.func_by_qname and self._is_internal(abs_target):
                    init_targets.append(abs_target)
        else:
            # Absolute target
            init_target = f"{target}.__init__"
            if init_target in self.func_by_qname and self._is_internal(init_target):
                init_targets.append(init_target)
                
        return init_targets
        
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
            print(f"  This may result in incomplete dependency ordering.")
            # Still return partial order - better than nothing
        return out


class _CallFinder(ast.NodeVisitor):
    """Find function calls within a function"""
    
    def __init__(self):
        self.calls = set()
        
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            # Direct function calls like function_name() or ClassName()
            self.calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            # Handle method calls like obj.method() or obj.subobj.method()
            if isinstance(node.func.value, ast.Name):
                # Simple case: obj.method()
                method_name = node.func.attr
                obj_name = node.func.value.id
                
                # Skip common built-in methods that are likely not user-defined functions
                builtin_methods = BUILTIN_METHODS
                
                if method_name not in builtin_methods:
                    method_call = f"{obj_name}.{method_name}"
                    self.calls.add(method_call)
            elif isinstance(node.func.value, ast.Attribute):
                # Complex case: obj.subobj.method() -> need to build the full chain
                method_name = node.func.attr
                chain_parts = []
                current = node.func.value
                
                # Walk up the attribute chain
                while isinstance(current, ast.Attribute):
                    chain_parts.append(current.attr)
                    current = current.value
                
                if isinstance(current, ast.Name):
                    chain_parts.append(current.id)
                    chain_parts.reverse()
                    
                    # For complex chains like os.path.exists, we want to capture
                    # the immediate parent as the owner: path.exists
                    if len(chain_parts) >= 2:
                        owner = chain_parts[-1]  # 'path' in os.path.exists
                        full_call = f"{owner}.{method_name}"
                        self.calls.add(full_call)
            else:
                # Only add the method name if it's likely a user-defined method
                method_name = node.func.attr
                builtin_attrs = BUILTIN_ATTRS
                if method_name not in builtin_attrs:
                    self.calls.add(method_name)
                
        self.generic_visit(node)


class _ImportFinder(ast.NodeVisitor):
    """Find imports within a function or scope"""
    
    def __init__(self):
        self.imports = set()
        self.aliases = {}
        self.file_path = None  # Set by caller for logging
        
    def visit_Import(self, node):
        for alias in node.names:
            # import pkg.utils as u
            fq = alias.name  # 'pkg.utils'
            local = alias.asname or alias.name.split('.')[-1]
            self.aliases[local] = fq
            self.imports.add(alias.name)
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        base = node.module or ""
        for alias in node.names:
            if alias.name == '*':
                logging.warning(f"Wildcard import `from {base} import *` detected in {self.file_path}. "
                              f"Dependency resolution may be incomplete.")
                continue  # Skip processing the '*'
            
            local = alias.asname or alias.name
            # from pkg.utils import foo as bar => 'pkg.utils.foo'
            target = f"{base}.{alias.name}" if base else alias.name
            self.aliases[local] = target
            self.imports.add(f"{base}.{alias.name}" if base else alias.name)
        self.generic_visit(node)


class _PythonASTAnalyzer(ast.NodeVisitor):
    """AST visitor for analyzing Python function dependencies"""
    
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.source_lines = source.splitlines()
        self.functions: List[FunctionInfo] = []
        self.current_class = None
        
        # Use _ImportFinder to handle all module-level imports
        import_finder = _ImportFinder()
        import_finder.file_path = file_path  # Add file_path for logging
        tree = ast.parse(source)
        import_finder.visit(tree)
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
        # qualify by module path from file path
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
        end_line = node.end_lineno or start_line
        source_lines = self.source_lines[start_line-1:end_line]
        source_code = '\n'.join(source_lines)

        signature = self._get_function_signature(node)
        docstring = ast.get_docstring(node) or ""
        
        # Detect decorator types
        is_static = any(isinstance(d, ast.Name) and d.id == 'staticmethod' for d in node.decorator_list)
        is_class = any(isinstance(d, ast.Name) and d.id == 'classmethod' for d in node.decorator_list)
        func_kind = 'static' if is_static else ('class' if is_class else 'inst')

        # Find function calls
        call_finder = _CallFinder()
        call_finder.visit(node)
        
        # Find function-level imports
        import_finder = _ImportFinder()
        import_finder.visit(node)

        # Combine module-level and function-level imports
        all_imports = self.imports.copy()
        all_imports.update(import_finder.imports)
        
        # Combine module-level and function-level aliases
        all_aliases = self.local_aliases.copy()
        all_aliases.update(import_finder.aliases)

        # Normalize to (shortname, scope_tag, owner)
        normalized: Set[Tuple[str, str, Optional[str]]] = set()
        for c in call_finder.calls:
            if c.startswith('self.') or c.startswith('cls.'):
                normalized.add((c.split('.', 1)[1], 'CLASS_LOCAL', None))
            elif '.' in c:
                owner, meth = c.split('.', 1)
                normalized.add((meth, 'OBJ', owner))  # keep owner!
            else:
                normalized.add((c, 'UNSCOPED', None))

        # Drop dunders like __len__, __repr__ and noisy attributes
        noisy = {'__call__'}
        normalized = {d for d in normalized if d[0] not in noisy and not (d[0].startswith('__') and d[0].endswith('__'))}

        return FunctionInfo(
            name=full_func_name,
            file_path=self.file_path,
            line_number=start_line,
            source_code=source_code,
            dependencies=set(normalized),                # triples now
            calls=set(x[0] for x in normalized),         # shortnames, for display only
            imports=all_imports,                         # include function-level imports
            signature=signature,
            docstring=docstring,
            source_aliases=all_aliases,                  # include function-level aliases
            kind=func_kind
        )
        
    def _get_function_signature(self, node) -> str:
        """Get function signature as string"""
        args = []
        for arg in node.args.args:
            args.append(arg.arg)
            
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
        
        if archive_path.suffix.lower() == '.whl':
            if not WHEEL_SUPPORT:
                logging.warning("wheel package not available, treating as zip file")
                
        # Extract as zip file (both .zip and .whl are zip formats)
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
    
    def __init__(self, codebase_path: str, function_snippet_file: str):
        self.codebase_path = codebase_path
        self.function_snippet_file = function_snippet_file
        self.extractor = CodebaseExtractor()
        self.extracted_dir: Optional[str] = None
        
    def run(self) -> Dict[str, Any]:
        """Run the complete analysis"""
        keep = bool(os.environ.get("CDA_KEEP_EXTRACTED"))
        start_time = time.time()
        try:
            # Step 1: Extract codebase
            print(f"Extracting codebase from {self.codebase_path}...")
            extract_start = time.time()
            self.extracted_dir = self.extractor.extract_archive(self.codebase_path)
            extract_time = time.time() - extract_start
            print(f"Extracted to: {self.extracted_dir} ({extract_time:.2f}s)")
            
            # Step 2: Read function snippet
            print(f"Reading function snippet from {self.function_snippet_file}...")
            with open(self.function_snippet_file, 'r', encoding='utf-8') as f:
                function_snippet = f.read().strip()
                
            # Step 3: Find the function in the codebase
            print("Searching for function in codebase...")
            search_start = time.time()
            search_result = self._find_function_in_codebase(function_snippet)
            search_time = time.time() - search_start
            
            if not search_result:
                total_time = time.time() - start_time
                return {
                    'error': 'Function not found in codebase',
                    'function_snippet': function_snippet,
                    'timing': {
                        'total_time': total_time,
                        'extract_time': extract_time,
                        'search_time': search_time
                    }
                }
                
            # Step 4: Analyze dependencies
            print("Analyzing function dependencies...")
            analysis_start = time.time()
            dependency_result = self._analyze_dependencies(search_result)
            analysis_time = time.time() - analysis_start
            
            total_time = time.time() - start_time
            
            return {
                'success': True,
                'function_found': search_result,
                'dependencies': dependency_result,
                'analyzer': dependency_result.get('analyzer'),  # Pass the analyzer from dependency result
                'codebase_path': self.codebase_path,
                'extracted_to': self.extracted_dir if keep else None,
                'timing': {
                    'total_time': total_time,
                    'extract_time': extract_time,
                    'search_time': search_time,
                    'analysis_time': analysis_time
                }
            }
            
        except Exception as e:
            total_time = time.time() - start_time
            return {
                'error': str(e),
                'codebase_path': self.codebase_path,
                'timing': {
                    'total_time': total_time
                }
            }
        finally:
            # Clean up
            if not keep:
                self.extractor.cleanup()
            
    def _find_function_in_codebase(self, function_snippet: str) -> Optional[Dict[str, Any]]:
        """Find the function in the extracted codebase"""
        content_search = ContentSearchEngine(self.extracted_dir)
        
        # Detect language from snippet
        snippet_language = self._detect_snippet_language(function_snippet)
        print(f"Detected snippet language: {snippet_language}")
        
        # Extract function name from snippet
        function_name = self._extract_function_name(function_snippet, snippet_language)
        
        # If function_name is a qualified name, skip file search and use it directly
        if function_name and '.' in function_name and function_name.count('.') >= 2:
            # This looks like a qualified function name, use it directly
            return {
                'file_path': 'N/A - using qualified name',
                'line_number': 0,
                'function_name': function_name,
                'search_method': 'qualified_name',
                'language': snippet_language
            }
        
        if not function_name:
            # Fallback to content search
            file_patterns = ['*.py']
            search_result = content_search.search_content(
                function_snippet[:100],  # Search first 100 chars
                file_patterns=file_patterns,
                max_results=10
            )
            
            if search_result.matches:
                best_match = search_result.matches[0]
                return {
                    'file_path': best_match.file_path,
                    'line_number': best_match.line_number,
                    'function_name': 'unknown',
                    'search_method': 'content_match',
                    'language': snippet_language
                }
                
            return None
            
        # Search for function definition - Python only
        search_patterns = [
            f"def\\s+{function_name}\\s*\\(",
            f"async\\s+def\\s+{function_name}\\s*\\(",
            f"class.*{function_name}.*:",
        ]
        file_patterns = ['*.py']
        
        for pattern in search_patterns:
            search_result = content_search.search_content(
                pattern,
                file_patterns=file_patterns,
                is_regex=True,
                max_results=5
            )
            
            if search_result.matches:
                best_match = search_result.matches[0]
                return {
                    'file_path': best_match.file_path,
                    'line_number': best_match.line_number,
                    'function_name': function_name,
                    'search_method': 'function_definition',
                    'language': snippet_language
                }
                
        return None
        
    def _detect_snippet_language(self, snippet: str) -> str:
        """Detect the language of the function snippet"""
        # Python indicators    
        if any(keyword in snippet for keyword in ['def ', 'async def', 'import ', 'from ']):
            return 'python'
        # Default to python for ambiguous cases
        else:
            return 'python'
        
    def _extract_function_name(self, snippet: str, language: str = 'python') -> Optional[str]:
        """Extract function name from code snippet"""
        # First check if snippet is already a qualified function name
        stripped = snippet.strip()
        # Enhanced heuristic for qualified names - allow function calls too
        if '.' in stripped and not any(keyword in stripped for keyword in ['def ', 'class ', 'import ', '{', '}', '\n', 'if ', 'for ', 'while ', 'try:', 'except']):
            # Remove function call parentheses if present: "test.func()" -> "test.func"
            clean_name = stripped.split('(')[0].strip()
            if clean_name.replace('.', '_').replace('_', '').isalnum():
                # Looks like a qualified name (e.g., "test.models.UserRepository.save" or "test.func()")
                return clean_name
        
        # Try to parse as Python code first
        try:
            tree = ast.parse(snippet)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node.name
        except SyntaxError:
            pass
            
        # Fallback to regex for Python
        patterns = [
            r'def\s+(\w+)\s*\(',
            r'async\s+def\s+(\w+)\s*\(',
            r'class\s+(\w+).*:',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, snippet)
            if match:
                return match.group(1)
        
        # If it's just a function name without code structure
        if stripped and stripped.replace('.', '_').replace('_', '').isalnum():
            return stripped.strip()  # Ensure proper stripping
                
        return None
        
    def _analyze_dependencies(self, function_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze function dependencies"""
        # Only analyze Python codebases
        analyzer = PythonDependencyAnalyzer(self.extracted_dir)
        
        # Analyze entire codebase
        analyzer.analyze_codebase()
        
        function_name = function_info['function_name']
        
        # Try to find the function, considering it might be a method
        # Look for the function in different forms
        possible_names = [function_name]
        
        # If it looks like a method name, try to find it as part of classes
        for qname in analyzer.func_by_qname.keys():
            if qname.endswith(f".{function_name}"):
                possible_names.append(qname)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_names = []
        for name in possible_names:
            if name not in seen:
                seen.add(name)
                unique_names.append(name)
        possible_names = unique_names
            
        found_function_name = None
        matching_functions = []
        
        # Find all matches in the codebase
        for name in possible_names:
            if name in analyzer.func_by_qname:
                matching_functions.append(name)
                
        if not matching_functions:
            print(f"Available functions: {list(analyzer.func_by_qname.keys())}")
            return {
                'dependency_order': [],
                'detailed_dependencies': [],
                'total_dependencies': 0,
                'analysis_method': 'python_function_not_found',
                'error': f'Function {function_name} not found in analyzed functions',
                'analyzer': analyzer  # Pass analyzer even in error cases
            }
        elif len(matching_functions) == 1:
            found_function_name = matching_functions[0]
        else:
            # Multiple matches - treat as ambiguous
            return {
                'dependency_order': [],
                'detailed_dependencies': [],
                'total_dependencies': 0,
                'analysis_method': 'ambiguous_function',
                'ambiguous_function': True,
                'candidates': matching_functions[:10],  # Limit to first 10
                'error': f'Function name "{function_name}" is ambiguous. Multiple matches found.',
                'analyzer': analyzer
            }
        
        dependencies_result = analyzer.find_function_dependencies(found_function_name, organize_by_levels=True)
        
        # Add the analyzer instance to the result for access to function details
        dependencies_result['analyzer'] = analyzer
        
        return dependencies_result


def main():
    """Main entry point"""
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    parser = argparse.ArgumentParser(
        description='Analyze Python codebase dependencies from function snippet',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python codebase_dependency_analyzer.py mypackage.whl function_snippet.txt
  python codebase_dependency_analyzer.py codebase.zip snippet.py
        """
    )
    
    parser.add_argument('codebase', help='Path to .whl or .zip file containing the codebase')
    parser.add_argument('snippet', help='Path to text file containing function snippet')
    parser.add_argument('--output', '-o', help='Output file for results (default: stdout)')
    parser.add_argument('--format', choices=['json', 'text'], default='text',
                       help='Output format (default: text)')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.codebase):
        print(f"Error: Codebase file not found: {args.codebase}", file=sys.stderr)
        return 1
        
    if not os.path.exists(args.snippet):
        print(f"Error: Function snippet file not found: {args.snippet}", file=sys.stderr)
        return 1
    
    # Validate file extensions
    codebase_ext = Path(args.codebase).suffix.lower()
    if codebase_ext not in ['.zip', '.whl']:
        print(f"Error: Unsupported codebase file type: {codebase_ext}. Expected .zip or .whl", file=sys.stderr)
        return 1
        
    # Run analysis
    runner = AnalysisRunner(args.codebase, args.snippet)
    result = runner.run()
    
    # Format output
    if args.format == 'json':
        output = json.dumps(result, indent=2, default=str)
    else:
        output = _format_text_output(result)
        
    # Write output
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Results written to: {args.output}")
    else:
        # Handle Unicode encoding for Windows console
        try:
            print(output)
        except UnicodeEncodeError:
            # Fallback to ASCII-safe output
            ascii_safe_output = output.encode('ascii', errors='replace').decode('ascii')
            print(ascii_safe_output)
        
    return 0 if result.get('success') else 1


def _format_text_output(result: Dict[str, Any]) -> str:
    """Format result as human-readable text with level-based dependency organization"""
    if 'error' in result:
        return f"Error: {result['error']}"
        
    # Check for dependency-level errors first
    deps = result.get('dependencies', {})
    if deps.get('error'):
        if deps.get('ambiguous_function'):
            output = ["Codebase Dependency Analysis Results", "=" * 40, ""]
            output.append("⚠️  Function name is ambiguous!")
            cands = deps.get('candidates', [])
            if cands:
                output.append("Available candidates:")
                for i, cand in enumerate(cands[:10], 1):  # Show max 10
                    output.append(f"  {i}. {cand}")
                output.append("")
                output.append("Please specify the fully qualified name (e.g., test.models.UserRepository.save)")
            return "\n".join(output)
        else:
            return f"Error: {deps['error']}"
        
    # Check for ambiguous function
    if deps.get('ambiguous_function'):
        # This section is now handled above in error checking
        pass
    output = ["Codebase Dependency Analysis Results"]
    output.append("=" * 40)
    output.append("")
    
    # Function found info
    func_info = result['function_found']
    output.append(f"Function found: {func_info['function_name']}")
    output.append(f"File: {func_info['file_path']}")
    output.append(f"Line: {func_info['line_number']}")
    output.append(f"Search method: {func_info['search_method']}")
    
    # Add timing information
    timing = result.get('timing', {})
    if timing:
        output.append("")
        output.append("Performance Metrics:")
        output.append("-" * 20)
        output.append(f"Total Time: {timing.get('total_time', 0):.2f}s")
        if 'extract_time' in timing:
            output.append(f"Extraction Time: {timing['extract_time']:.2f}s")
        if 'search_time' in timing:
            output.append(f"Search Time: {timing['search_time']:.2f}s")
        if 'analysis_time' in timing:
            output.append(f"Analysis Time: {timing['analysis_time']:.2f}s")
    
    output.append("")
    
    # Dependencies - organize by levels if available
    dependencies_by_level = deps.get('dependencies_by_level', {})
    user_defined_deps = deps.get('user_defined_order', [])
    external_deps = deps.get('external_dependencies', [])
    
    if dependencies_by_level:
        output.append("Dependencies by Level:")
        output.append("=" * 25)
        
        total_deps = sum(len(deps_set) for deps_set in dependencies_by_level.values())
        output.append(f"Total Dependencies: {total_deps}")
        output.append("")
        
        for level in sorted(dependencies_by_level.keys()):
            level_deps = sorted(dependencies_by_level[level])
            if level == 0:
                level_name = "Direct Dependencies"
            else:
                level_name = f"Level-{level} Dependencies"
                
            output.append(f"{level_name} ({len(level_deps)} functions):")
            output.append("-" * (len(level_name) + 20))
            
            for i, dep_name in enumerate(level_deps, 1):
                output.append(f"  {i}. {dep_name}")
            output.append("")
    else:
        # Fallback to flat organization
        all_deps = user_defined_deps + external_deps
        output.append(f"Dependencies ({len(all_deps)} total):")
        output.append("-" * 30)
        
        for i, dep_name in enumerate(all_deps, 1):
            output.append(f"{i}. {dep_name}")
        output.append("")

    # Show all detected calls if available
    all_deps_detected = deps.get('all_dependencies', set())
    if all_deps_detected:
        output.append("All Detected Function/Method Calls:")
        output.append("-" * 35)
        sorted_detected = sorted(list(all_deps_detected))
        for i in range(0, len(sorted_detected), 5):  # Show 5 per line
            line_deps = sorted_detected[i:i+5]
            output.append(", ".join(line_deps))
        output.append("")
    
    # Detailed Dependency Information organized by levels
    output.append("Detailed Dependency Information:")
    output.append("=" * 35)
    
    # Get the analyzer from the result to access function details
    analyzer = result.get('analyzer')
    if not analyzer:
        output.append("(Function source code not available - analyzer instance not found)")
        output.append("This may indicate an error during codebase analysis.")
        return "\n".join(output)
    
    # Show detailed info organized by levels if available
    if dependencies_by_level:
        for level in sorted(dependencies_by_level.keys()):
            level_deps = sorted(dependencies_by_level[level])
            if level == 0:
                level_name = "DIRECT DEPENDENCIES"
            else:
                level_name = f"LEVEL-{level} DEPENDENCIES"
            
            output.append(f"\n{level_name}")
            output.append("=" * len(level_name))
            
            for i, dep_name in enumerate(level_deps, 1):
                output.append(f"\n{level}.{i} {dep_name}")
                output.append("=" * (len(dep_name) + 10))
                
                # Get function info from the analyzer
                if dep_name in analyzer.func_by_qname:
                    func_info = analyzer.func_by_qname[dep_name]
                    output.append(f"File: {func_info.file_path}")
                    output.append(f"Line: {func_info.line_number}")
                    output.append(f"Signature: {func_info.signature}")
                    
                    if func_info.docstring:
                        output.append(f"Docstring: {func_info.docstring}")
                    
                    # Show nested dependencies for Level-1 functions
                    if level == 1:
                        nested_deps = analyzer._get_nested_dependency_levels(dep_name, dependencies_by_level)
                        if nested_deps:
                            output.append("\nNested Dependencies:")
                            for nested_level, nested_funcs in sorted(nested_deps.items()):
                                if nested_funcs:
                                    output.append(f"  Level-{nested_level}: {', '.join(sorted(nested_funcs))}")
                    
                    # Show direct dependencies for Level-2+ functions
                    elif level > 1 and dep_name in analyzer.func_by_qname:
                        func_deps = analyzer.func_by_qname[dep_name].dependencies
                        resolved_deps = [analyzer._resolve_dependency(dep_name, d) for d in func_deps]
                        resolved_deps = [d for d in resolved_deps if d and d in analyzer.func_by_qname]
                        if resolved_deps:
                            output.append(f"\nDirect Dependencies: {', '.join(sorted(resolved_deps))}")
                    
                    output.append("\nSource Code:")
                    output.append("-" * 60)
                    for line_num, line in enumerate(func_info.source_code.splitlines(), func_info.line_number):
                        output.append(f"{line_num:4d}: {line}")
                    output.append("-" * 60)
                else:
                    # Check if it's an external dependency with known info
                    external_info = analyzer._get_external_function_info(dep_name)
                    if external_info:
                        output.append(f"File: {external_info['file']}")
                        output.append(f"Line: {external_info['line']}")
                        output.append(f"Signature: {external_info['signature']}")
                        
                        output.append("\nSource Code:")
                        output.append("-" * 60)
                        output.append(external_info['source'])
                        output.append("-" * 60)
                        
                        # Show nested dependencies if any
                        nested_deps = external_info.get('dependencies', [])
                        if nested_deps:
                            output.append(f"Nested Dependencies: {', '.join(nested_deps)}")
                    else:
                        output.append("(External dependency - source not available)")
    else:
        # Fallback to flat format
        all_deps = user_defined_deps + external_deps
        if all_deps:
            for i, dep_name in enumerate(all_deps, 1):
                output.append(f"\n{i}. {dep_name}")
                output.append("=" * (len(dep_name) + 10))
                
                # Get function info from the analyzer
                if dep_name in analyzer.func_by_qname:
                    func_info = analyzer.func_by_qname[dep_name]
                    output.append(f"File: {func_info.file_path}")
                    output.append(f"Line: {func_info.line_number}")
                    output.append(f"Signature: {func_info.signature}")
                    
                    if func_info.docstring:
                        output.append(f"Docstring: {func_info.docstring}")
                    
                    output.append("\nSource Code:")
                    output.append("-" * 60)
                    for line_num, line in enumerate(func_info.source_code.splitlines(), func_info.line_number):
                        output.append(f"{line_num:4d}: {line}")
                    output.append("-" * 60)
                else:
                    # Check if it's an external dependency with known info
                    external_info = analyzer._get_external_function_info(dep_name)
                    if external_info:
                        output.append(f"File: {external_info['file']}")
                        output.append(f"Line: {external_info['line']}")
                        output.append(f"Signature: {external_info['signature']}")
                        
                        output.append("\nSource Code:")
                        output.append("-" * 60)
                        output.append(external_info['source'])
                        output.append("-" * 60)
                        
                        # Show nested dependencies if any
                        nested_deps = external_info.get('dependencies', [])
                        if nested_deps:
                            output.append(f"Nested Dependencies: {', '.join(nested_deps)}")
                    else:
                        output.append("(External dependency - source not available)")
            
    return "\n".join(output)


if __name__ == '__main__':
    sys.exit(main())
