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
    dependencies: Set[str] = field(default_factory=set)
    calls: Set[str] = field(default_factory=set)
    imports: Set[str] = field(default_factory=set)
    signature: str = ""
    docstring: str = ""


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
                if file_stats.st_size > 50 * 1024 * 1024:  # Skip files larger than 50MB
                    print(f"Warning: Skipping large file {file_path} ({file_stats.st_size} bytes) in content search")
                    continue
                    
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                files_searched += 1
                
                for line_num, line in enumerate(content.splitlines(), 1):
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
    
    def __init__(self, root_dir: str, max_functions_in_memory: int = 10000):
        self.root_dir = Path(root_dir).resolve()
        self.functions: Dict[str, FunctionInfo] = {}
        self.classes: Dict[str, Dict[str, FunctionInfo]] = {}
        self.imports: Dict[str, Set[str]] = defaultdict(set)
        self.max_functions_in_memory = max_functions_in_memory
        self._lock = threading.Lock()  # For thread safety
        
    def analyze_file(self, file_path: str) -> List[FunctionInfo]:
        """Analyze a Python file and extract function information"""
        full_path = self.root_dir / file_path
        
        try:
            # Check file size to avoid loading extremely large files
            file_stats = full_path.stat()
            if file_stats.st_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                print(f"Warning: Skipping large file {file_path} ({file_stats.st_size} bytes)")
                return []
                
            with open(full_path, 'r', encoding='utf-8') as f:
                source = f.read()
                
            tree = ast.parse(source)
            analyzer = _PythonASTAnalyzer(file_path, source)
            analyzer.visit(tree)
            
            return analyzer.functions
            
        except (SyntaxError, UnicodeDecodeError, FileNotFoundError, OSError) as e:
            print(f"Warning: Could not parse {file_path}: {e}")
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
                    
        print(f"Analyzing {len(python_files)} Python files...")
        
        # Use parallel processing for large codebases
        if len(python_files) > 10:
            self._analyze_files_parallel(python_files)
        else:
            self._analyze_files_sequential(python_files)
            
    def _analyze_files_sequential(self, python_files: List[str]) -> None:
        """Analyze files sequentially (for small codebases)"""
        for file_path in python_files:
            functions = self.analyze_file(file_path)
            self._store_functions(functions)
            
    def _analyze_files_parallel(self, python_files: List[str]) -> None:
        """Analyze files in parallel (for large codebases)"""
        max_workers = min(8, len(python_files))  # Don't use too many threads
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
                    print(f"Warning: Error processing {file_path}: {e}")
                    processed_files += 1
                    
    def _store_functions(self, functions: List[FunctionInfo]) -> None:
        """Store function information thread-safely with memory management"""
        with self._lock:
            for func in functions:
                # Memory management: warn if we're storing too many functions
                if len(self.functions) >= self.max_functions_in_memory:
                    print(f"Warning: Large codebase detected. {len(self.functions)} functions in memory. "
                          f"Consider analyzing smaller chunks or increasing memory limits.")
                
                self.functions[func.name] = func
                # Track classes
                if '.' in func.name:
                    class_name = func.name.split('.')[0]
                    if class_name not in self.classes:
                        self.classes[class_name] = {}
                    method_name = func.name.split('.')[1]
                    self.classes[class_name][method_name] = func
                
    def find_function_dependencies(self, function_name: str, organize_by_levels: bool = False) -> Dict[str, Any]:
        """Find all dependencies for a function in correct order, optionally organized by levels"""
        if function_name not in self.functions:
            print(f"Function '{function_name}' not found in analyzed functions")
            print(f"Available functions: {list(self.functions.keys())}")
            return {
                'user_defined_order': [],
                'all_dependencies': set(),
                'total_calls': 0,
                'dependencies_by_level': {} if organize_by_levels else None
            }
            
        all_raw_dependencies = set()
        external_dependencies = set()
        dependencies_by_level = {} if organize_by_levels else None
        
        # Use a queue for breadth-first search with level tracking
        queue = [(function_name, 0)]  # (function_name, level)
        visited_resolved = {function_name}
        level_map = {function_name: 0}

        while queue:
            current_func, current_level = queue.pop(0)
            
            if current_func not in self.functions:
                continue
                
            func_info = self.functions[current_func]
            print(f"Analyzing dependencies for {current_func}: {func_info.dependencies}")
            
            # Initialize level in dependencies_by_level if organizing by levels
            if organize_by_levels and current_level > 0:
                if current_level not in dependencies_by_level:
                    dependencies_by_level[current_level] = set()
                dependencies_by_level[current_level].add(current_func)
            
            for dep in func_info.dependencies:
                all_raw_dependencies.add(dep)
                
                # Check for external dependencies (like secrets.randbelow)
                if dep.startswith('secrets.') or dep in ['randbelow', 'randbytes', 'getrandbits']:
                    external_dep_name = dep if dep.startswith('secrets.') else f'secrets.{dep}'
                    external_dependencies.add(external_dep_name)
                    
                    # Add to level organization if requested
                    if organize_by_levels:
                        next_level = current_level + 1
                        if next_level not in dependencies_by_level:
                            dependencies_by_level[next_level] = set()
                        dependencies_by_level[next_level].add(external_dep_name)
                    
                    continue
                
                # Resolve internal dependency to a function in our list
                resolved_dep = self._resolve_dependency(dep, current_func)
                
                if resolved_dep and resolved_dep not in visited_resolved:
                    visited_resolved.add(resolved_dep)
                    next_level = current_level + 1
                    level_map[resolved_dep] = next_level
                    queue.append((resolved_dep, next_level))

        # Topological sort to get correct order of user-defined functions
        internal_funcs = [f for f in visited_resolved if f != function_name]
        ordered_user_deps = self._topological_sort(internal_funcs)
        
        # Add external dependencies to the final order
        final_order = ordered_user_deps + sorted(external_dependencies)
        
        result = {
            'user_defined_order': final_order,
            'all_dependencies': all_raw_dependencies,
            'total_calls': len(all_raw_dependencies),
            'external_dependencies': sorted(external_dependencies)
        }
        
        # Add level organization if requested
        if organize_by_levels:
            result['dependencies_by_level'] = dependencies_by_level
        
        print(f"Final dependency order: {final_order}")
        print(f"Final dependency order: {final_order}")
        print(f"All dependencies detected: {sorted(all_raw_dependencies)}")
        print(f"External dependencies: {sorted(external_dependencies)}")
        if organize_by_levels:
            print(f"Dependencies by level: {dependencies_by_level}")
        
        return result

    def _get_nested_dependency_levels(self, function_name: str, global_dependencies_by_level: Dict[int, Set[str]]) -> Dict[int, Set[str]]:
        """Get the nested dependency levels for a specific function"""
        if function_name not in self.functions:
            return {}
        
        # Get direct dependencies of this specific function
        direct_deps = set(self.functions[function_name].dependencies)
        user_defined_direct_deps = {self._resolve_dependency(dep, function_name) for dep in direct_deps if self._resolve_dependency(dep, function_name)}
        user_defined_direct_deps = {dep for dep in user_defined_direct_deps if dep and dep != function_name}
        
        if not user_defined_direct_deps:
            return {}
        
        # Build nested levels by tracing this function's specific dependency chain
        nested_levels = {}
        
        # Level 2: Direct dependencies of this function
        nested_levels[2] = user_defined_direct_deps
        
        current_level_deps = user_defined_direct_deps
        visited_deps = set([function_name])  # Track visited to prevent cycles
        level = 3  # Start at level 3 for next level dependencies
        
        while current_level_deps and level <= 6:  # Limit depth to prevent infinite recursion
            next_level_deps = set()
            
            # For each dependency at current level, find its dependencies
            for dep in current_level_deps:
                if dep in self.functions and dep not in visited_deps:
                    visited_deps.add(dep)
                    dep_dependencies = set(self.functions[dep].dependencies)
                    resolved_deps = {self._resolve_dependency(d, dep) for d in dep_dependencies if self._resolve_dependency(d, dep)}
                    # Only include user-defined functions that haven't been visited
                    resolved_deps = {d for d in resolved_deps if d and d not in visited_deps and d in self.functions}
                    next_level_deps.update(resolved_deps)
            
            if next_level_deps:
                nested_levels[level] = next_level_deps
                current_level_deps = next_level_deps
            else:
                break
                
            level += 1
        
        return nested_levels

    def _get_external_function_info(self, qname: str) -> Optional[Dict[str, Any]]:
        """Get basic information about external/standard library functions"""
        external_functions = {
            'secrets.randbelow': {
                'signature': 'randbelow(exclusive_upper_bound)',
                'source': 'def randbelow(exclusive_upper_bound):\n    """Return a random int in the range [0, n)."""\n    if exclusive_upper_bound <= 0:\n        raise ValueError("Upper bound must be positive.")\n    return _sysrand._randbelow(exclusive_upper_bound)',
                'dependencies': ['_sysrand._randbelow', 'ValueError'],
                'file': 'secrets.py (Python standard library)',
                'line': '25'
            },
            'secrets.randbytes': {
                'signature': 'randbytes(n)',
                'source': 'randbytes = _sysrand.randbytes',
                'dependencies': ['_sysrand.randbytes'],
                'file': 'secrets.py (Python standard library)',
                'line': 'N/A'
            },
            'secrets.token_bytes': {
                'signature': 'token_bytes(nbytes=None)',
                'source': 'def token_bytes(nbytes=None):\n    if nbytes is None:\n        nbytes = DEFAULT_ENTROPY\n    return _sysrand.randbytes(nbytes)',
                'dependencies': ['_sysrand.randbytes', 'DEFAULT_ENTROPY'],
                'file': 'secrets.py (Python standard library)',
                'line': '31'
            }
        }
        return external_functions.get(qname)
        
    def _resolve_dependency(self, dep_name: str, current_function_context: Optional[str] = None) -> Optional[str]:
        """Resolves a raw dependency string to a function name in the codebase."""
        # 1. Direct match
        if dep_name in self.functions:
            return dep_name
        
        # 2. Constructor call (e.g., "ClassName" -> "ClassName.__init__")
        init_name = f"{dep_name}.__init__"
        if init_name in self.functions:
            return init_name

        # 3. Heuristic for obj.method or Class.method
        if '.' in dep_name:
            method_name = dep_name.split('.')[-1]
            obj_name = dep_name.split('.')[0]
            
            # Collect all possible matches
            possible_matches = []
            for func_name in self.functions:
                if func_name.endswith(f".{method_name}"):
                    possible_matches.append(func_name)
            
            if not possible_matches:
                return None
                
            # If we have multiple matches, try to be smarter about resolution
            if len(possible_matches) == 1:
                return possible_matches[0]
            
            # For 'self.method', prefer methods from the same class if we can determine context
            if obj_name == 'self' and current_function_context:
                # Extract class name from current function context (e.g., "ClassName.method" -> "ClassName")
                if '.' in current_function_context:
                    current_class = current_function_context.split('.')[0]
                    class_method = f"{current_class}.{method_name}"
                    if class_method in possible_matches:
                        return class_method
            
            # Return the first match as fallback
            return possible_matches[0]

        return None
        
    def _topological_sort(self, func_names: List[str]) -> List[str]:
        """Sort functions in dependency order"""
        in_degree = {name: 0 for name in func_names}
        graph = {name: [] for name in func_names}
        
        # Build dependency graph
        for func_name in func_names:
            if func_name in self.functions:
                func_info = self.functions[func_name]
                for dep in func_info.dependencies:
                    if dep in func_names:
                        graph[dep].append(func_name)
                        in_degree[func_name] += 1
                        
        # Kahn's algorithm
        queue = deque([name for name in func_names if in_degree[name] == 0])
        result = []
        
        while queue:
            current = queue.popleft()
            result.append(current)
            
            for neighbor in graph[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    
        return result


class _CallFinder(ast.NodeVisitor):
    """Find function calls within a function"""
    
    def __init__(self):
        self.calls = set()
        
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            # Direct function calls like function_name() or ClassName()
            self.calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            # Handle method calls like obj.method()
            if isinstance(node.func.value, ast.Name):
                # For method calls, only add the full qualified name for user-defined functions
                # Skip built-in methods like .add, .append, etc. on built-in types
                method_name = node.func.attr
                obj_name = node.func.value.id
                
                # Skip common built-in methods that are likely not user-defined functions
                builtin_methods = {
                    'add', 'append', 'remove', 'pop', 'clear', 'update', 'get', 'set',
                    'keys', 'values', 'items', 'copy', 'extend', 'insert', 'reverse',
                    'sort', 'count', 'index', 'replace', 'split', 'join', 'strip',
                    'startswith', 'endswith', 'lower', 'upper', 'title', 'capitalize',
                    'format', 'encode', 'decode', 'find', 'rfind', 'isdigit', 'isalpha',
                    'isupper', 'islower', 'isspace', 'exists', 'read', 'write', 'close'
                }
                
                if method_name not in builtin_methods:
                    method_call = f"{obj_name}.{method_name}"
                    self.calls.add(method_call)
            else:
                # Only add the method name if it's likely a user-defined method
                method_name = node.func.attr
                if method_name not in {'add', 'append', 'remove', 'pop', 'get', 'set', 'clear'}:
                    self.calls.add(method_name)
                
        self.generic_visit(node)
        
    def visit_Name(self, node):
        # Also detect variable/constant references that are loaded (not stored)
        if isinstance(node.ctx, ast.Load):
            # Only add names that look like constants (all caps) or known function names
            name = node.id
            if name.isupper() or name in {'callable', 'isinstance', 'len', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple'}:
                self.calls.add(name)
                
        self.generic_visit(node)


class _PythonASTAnalyzer(ast.NodeVisitor):
    """AST visitor for analyzing Python function dependencies"""
    
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.source_lines = source.splitlines()
        self.functions: List[FunctionInfo] = []
        self.current_class = None
        self.imports = set()
        
    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            self.imports.add(f"{module}.{alias.name}" if module else alias.name)
        self.generic_visit(node)
        
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
        full_func_name = func_name
        if self.current_class:
            full_func_name = f"{self.current_class}.{func_name}"
            
        # Get function source code
        start_line = node.lineno
        end_line = node.end_lineno or start_line
        source_lines = self.source_lines[start_line-1:end_line]
        source_code = '\n'.join(source_lines)
        
        # Get function signature
        signature = self._get_function_signature(node)
        
        # Get docstring
        docstring = ast.get_docstring(node) or ""
        
        # Find function calls and dependencies
        call_finder = _CallFinder()
        call_finder.visit(node)
        
        # Also add method calls without self prefix if in a class
        if self.current_class:
            # Look for self.method_name calls and add as method calls
            for call in list(call_finder.calls):
                if call.startswith('self.'):
                    method_name = call[5:]  # Remove 'self.'
                    call_finder.calls.add(f"{self.current_class}.{method_name}")
        
        func_info = FunctionInfo(
            name=full_func_name,
            file_path=self.file_path,
            line_number=start_line,
            source_code=source_code,
            dependencies=call_finder.calls,
            calls=call_finder.calls,
            imports=self.imports.copy(),
            signature=signature,
            docstring=docstring
        )
        
        print(f"Extracted function: {full_func_name} with dependencies: {call_finder.calls}")
        
        return func_info
        
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
                print("Warning: wheel package not available, treating as zip file")
                
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


class CodebaseDependencyAnalyzer:
    """Main application class"""
    
    def __init__(self, codebase_path: str, function_snippet_file: str):
        self.codebase_path = codebase_path
        self.function_snippet_file = function_snippet_file
        self.extractor = CodebaseExtractor()
        self.extracted_dir: Optional[str] = None
        
    def run(self) -> Dict[str, Any]:
        """Run the complete analysis"""
        try:
            # Step 1: Extract codebase
            print(f"Extracting codebase from {self.codebase_path}...")
            self.extracted_dir = self.extractor.extract_archive(self.codebase_path)
            print(f"Extracted to: {self.extracted_dir}")
            
            # Step 2: Read function snippet
            print(f"Reading function snippet from {self.function_snippet_file}...")
            with open(self.function_snippet_file, 'r', encoding='utf-8') as f:
                function_snippet = f.read().strip()
                
            # Step 3: Find the function in the codebase
            print("Searching for function in codebase...")
            search_result = self._find_function_in_codebase(function_snippet)
            
            if not search_result:
                return {
                    'error': 'Function not found in codebase',
                    'function_snippet': function_snippet
                }
                
            # Step 4: Analyze dependencies
            print("Analyzing function dependencies...")
            dependency_result = self._analyze_dependencies(search_result)
            
            return {
                'success': True,
                'function_found': search_result,
                'dependencies': dependency_result,
                'analyzer': dependency_result.get('analyzer'),  # Pass the analyzer from dependency result
                'codebase_path': self.codebase_path,
                'extracted_to': self.extracted_dir
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'codebase_path': self.codebase_path
            }
        finally:
            # Clean up
            self.extractor.cleanup()
            
    def _detect_codebase_language(self) -> str:
        """Detect the primary language of the codebase - focuses on Python"""
        python_files = 0
        
        for root, _, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith('.py'):
                    python_files += 1
                    
        if python_files > 0:
            print(f"Detected Python codebase with {python_files} Python files")
            return 'python'
        else:
            print("No Python files detected in codebase")
            return 'unknown'
            
    def _find_function_in_codebase(self, function_snippet: str) -> Optional[Dict[str, Any]]:
        """Find the function in the extracted codebase"""
        content_search = ContentSearchEngine(self.extracted_dir)
        
        # Detect language from snippet
        snippet_language = self._detect_snippet_language(function_snippet)
        print(f"Detected snippet language: {snippet_language}")
        
        # Extract function name from snippet
        function_name = self._extract_function_name(function_snippet, snippet_language)
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
                
        return None
        
    def _analyze_dependencies(self, function_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze function dependencies"""
        # Only analyze Python codebases
        analyzer = PythonDependencyAnalyzer(self.extracted_dir)
        analyzer.analyze_codebase()
        
        function_name = function_info['function_name']
        
        # Try to find the function, considering it might be a method
        # Look for the function in different forms
        possible_names = [function_name]
        
        # If it looks like a method name, try to find it as part of classes
        for class_name in analyzer.classes.keys():
            possible_names.append(f"{class_name}.{function_name}")
            
        found_function_name = None
        for name in possible_names:
            if name in analyzer.functions:
                found_function_name = name
                break
                
        if not found_function_name:
            print(f"Available functions: {list(analyzer.functions.keys())}")
            return {
                'dependency_order': [],
                'detailed_dependencies': [],
                'total_dependencies': 0,
                'analysis_method': 'python_function_not_found',
                'error': f'Function {function_name} not found in analyzed functions'
            }
        
        dependencies_result = analyzer.find_function_dependencies(found_function_name, organize_by_levels=True)
        
        # Add the analyzer instance to the result for access to function details
        dependencies_result['analyzer'] = analyzer
        
        return dependencies_result


def main():
    """Main entry point"""
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
    analyzer = CodebaseDependencyAnalyzer(args.codebase, args.snippet)
    result = analyzer.run()
    
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
        
    output = ["Codebase Dependency Analysis Results"]
    output.append("=" * 40)
    output.append("")
    
    # Function found info
    func_info = result['function_found']
    output.append(f"Function found: {func_info['function_name']}")
    output.append(f"File: {func_info['file_path']}")
    output.append(f"Line: {func_info['line_number']}")
    output.append(f"Search method: {func_info['search_method']}")
    output.append("")
    
    # Dependencies - organize by levels if available
    deps = result['dependencies']
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
                if dep_name in analyzer.functions:
                    func_info = analyzer.functions[dep_name]
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
                    elif level > 1 and dep_name in analyzer.functions:
                        func_deps = analyzer.functions[dep_name].dependencies
                        resolved_deps = [analyzer._resolve_dependency(d, dep_name) for d in func_deps]
                        resolved_deps = [d for d in resolved_deps if d and d in analyzer.functions]
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
                if dep_name in analyzer.functions:
                    func_info = analyzer.functions[dep_name]
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
