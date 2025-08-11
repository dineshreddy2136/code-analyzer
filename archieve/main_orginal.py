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
                
    def find_function_dependencies(self, function_name: str) -> Dict[str, Any]:
        """Find all dependencies for a function in correct order"""
        if function_name not in self.functions:
            print(f"Function '{function_name}' not found in analyzed functions")
            print(f"Available functions: {list(self.functions.keys())}")
            return {
                'user_defined_order': [],
                'all_dependencies': set(),
                'total_calls': 0
            }
            
        all_raw_dependencies = set()
        
        # Use a queue for breadth-first search
        queue = [function_name]
        visited_resolved = {function_name}

        while queue:
            current_func = queue.pop(0)
            
            if current_func not in self.functions:
                continue
                
            func_info = self.functions[current_func]
            print(f"Analyzing dependencies for {current_func}: {func_info.dependencies}")
            
            for dep in func_info.dependencies:
                all_raw_dependencies.add(dep)
                
                # Resolve dependency to a function in our list
                resolved_dep = self._resolve_dependency(dep)
                
                if resolved_dep and resolved_dep not in visited_resolved:
                    visited_resolved.add(resolved_dep)
                    queue.append(resolved_dep)

        # Topological sort to get correct order of user-defined functions
        ordered_user_deps = self._topological_sort(list(visited_resolved))
        
        # Check for circular dependencies
        if len(ordered_user_deps) < len(visited_resolved):
            missing_funcs = set(visited_resolved) - set(ordered_user_deps)
            print(f"Warning: Potential circular dependencies detected involving: {missing_funcs}")
        
        # The final list of dependencies to show should be the ordered user-defined ones
        final_order = [f for f in ordered_user_deps]
        
        result = {
            'user_defined_order': final_order,
            'all_dependencies': all_raw_dependencies,
            'total_calls': len(all_raw_dependencies)
        }
        
        print(f"Final dependency order: {final_order}")
        print(f"All dependencies detected: {sorted(all_raw_dependencies)}")
        return result
        
    def _resolve_dependency(self, dep_name: str) -> Optional[str]:
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
            # For "var.method", we can't know the type of "var", so we search for
            # any class method named "method". This is an approximation.
            method_name = dep_name.split('.')[-1]
            # Prefer matches where the class name seems plausible, but it's a guess.
            for func_name in self.functions:
                if func_name.endswith(f".{method_name}"):
                    return func_name  # Return the first match found

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
                # Add both the method call and just the method name
                method_call = f"{node.func.value.id}.{node.func.attr}"
                self.calls.add(method_call)
                # Also add just the method name for cross-reference
                self.calls.add(node.func.attr)
            else:
                # Add just the method name for complex attribute access
                self.calls.add(node.func.attr)
                
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
        
        dependencies_result = analyzer.find_function_dependencies(found_function_name)
        dependencies = dependencies_result['user_defined_order']
        all_deps = dependencies_result['all_dependencies']
        
        # Get detailed information for each dependency
        detailed_dependencies = []
        for dep_name in dependencies:
            if dep_name in analyzer.functions:
                func_info = analyzer.functions[dep_name]
                detailed_dependencies.append({
                    'name': func_info.name,
                    'file_path': func_info.file_path,
                    'line_number': func_info.line_number,
                    'signature': func_info.signature,
                    'source_code': func_info.source_code,
                    'docstring': func_info.docstring
                })
                
        return {
            'dependency_order': dependencies,
            'detailed_dependencies': detailed_dependencies,
            'total_dependencies': len(dependencies),
            'analysis_method': 'python_ast_based',
            'found_function_name': found_function_name,
            'language': 'python',
            'raw_calls': sorted(list(all_deps))
        }


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
    """Format result as human-readable text"""
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
    
    # Dependencies
    deps = result['dependencies']
    output.append(f"Dependencies ({deps['total_dependencies']} total):")
    output.append("-" * 30)
    
    for i, dep_name in enumerate(deps['dependency_order'], 1):
        output.append(f"{i}. {dep_name}")
        
    output.append("")

    if 'raw_calls' in deps and deps['raw_calls']:
        output.append("Raw Detected Function/Method Calls:")
        output.append("-" * 35)
        output.append(", ".join(deps['raw_calls']))
        output.append("")
    
    output.append("Detailed Dependency Information:")
    output.append("-" * 35)
    
    for dep in deps['detailed_dependencies']:
        output.append(f"\nFunction: {dep['name']}")
        output.append(f"  File: {dep['file_path']}")
        output.append(f"  Line: {dep['line_number']}")
        output.append(f"  Signature: {dep['signature']}")
        
        if dep['docstring']:
            output.append(f"  Docstring: {dep['docstring']}")
            
        output.append(f"  Complete Source Code ({len(dep['source_code'].splitlines())} lines):")
        output.append(f"  {'-' * 60}")
        for line_num, line in enumerate(dep['source_code'].splitlines(), 1):
            output.append(f"    {line_num:3d}: {line}")
        output.append(f"  {'-' * 60}")
            
    return "\n".join(output)


if __name__ == '__main__':
    sys.exit(main())
