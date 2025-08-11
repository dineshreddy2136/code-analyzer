#!/usr/bin/env python3
"""
Enhanced Codebase Dependency Analyzer

An improved version with:
- Indexed Dependency Resolution (O(1) lookup)
- Context-Aware Scoring
- Advanced Caching/Memoization
- Data Flow Analysis
- Fuzzy String Matching

All improvements maintain backward compatibility with the original analyzer.
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
import functools
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
import shutil
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

# Import the original classes we'll extend
from code_analyzer import (
    FileMatch, FunctionInfo, SearchResult, FileSearchEngine, 
    ContentSearchEngine, CodebaseExtractor, _CallFinder, _PythonASTAnalyzer
)

# Try to import optional dependencies
try:
    import wheel
    WHEEL_SUPPORT = True
except ImportError:
    WHEEL_SUPPORT = False

@dataclass
class EnhancedFunctionInfo(FunctionInfo):
    """Extended function information with additional metadata"""
    variable_types: Dict[str, Set[str]] = field(default_factory=dict)
    conditional_calls: Set[str] = field(default_factory=set)
    loop_calls: Set[str] = field(default_factory=set)
    parameter_types: Dict[str, str] = field(default_factory=dict)
    return_type: Optional[str] = None
    complexity_score: float = 0.0
    
@dataclass
class DependencyMatch:
    """Represents a dependency match with confidence score"""
    target_function: str
    source_function: str
    confidence: float
    match_type: str  # 'direct', 'constructor', 'method', 'fuzzy', 'context'
    reasoning: str

class DependencyIndex:
    """High-performance O(1) dependency lookup system"""
    
    def __init__(self):
        # Core indexes for O(1) lookups
        self.function_index: Dict[str, EnhancedFunctionInfo] = {}
        self.method_index: Dict[str, List[str]] = defaultdict(list)  # method_name -> [full_names]
        self.class_index: Dict[str, Set[str]] = defaultdict(set)  # class_name -> methods
        self.import_index: Dict[str, Set[str]] = defaultdict(set)  # file -> imports
        self.reverse_import_index: Dict[str, Set[str]] = defaultdict(set)  # import -> files
        
        # Context awareness indexes
        self.file_functions: Dict[str, Set[str]] = defaultdict(set)  # file -> functions
        self.package_functions: Dict[str, Set[str]] = defaultdict(set)  # package -> functions
        self.similar_functions: Dict[str, List[str]] = defaultdict(list)  # func -> similar_funcs
        
        # Performance tracking
        self.lookup_stats = {'hits': 0, 'misses': 0, 'fuzzy_matches': 0}
    
    def build_indexes(self, functions: Dict[str, EnhancedFunctionInfo]) -> None:
        """Build all indexes from function data - O(n) preprocessing"""
        print("Building enhanced dependency indexes...")
        start_time = time.time()
        
        # Clear existing indexes
        self._clear_indexes()
        
        # Build core indexes
        for func_name, func_info in functions.items():
            self._index_function(func_name, func_info)
        
        # Build similarity indexes
        self._build_similarity_index()
        
        build_time = time.time() - start_time
        print(f"Indexes built in {build_time:.2f}s for {len(functions)} functions")
        print(f"Method index: {len(self.method_index)} unique method names")
        print(f"Class index: {len(self.class_index)} classes")
    
    def _clear_indexes(self):
        """Clear all indexes"""
        self.function_index.clear()
        self.method_index.clear()
        self.class_index.clear()
        self.import_index.clear()
        self.reverse_import_index.clear()
        self.file_functions.clear()
        self.package_functions.clear()
        self.similar_functions.clear()
    
    def _index_function(self, func_name: str, func_info: EnhancedFunctionInfo):
        """Index a single function"""
        self.function_index[func_name] = func_info
        
        # Index by file
        self.file_functions[func_info.file_path].add(func_name)
        
        # Index by package
        package = func_info.file_path.split('/')[0] if '/' in func_info.file_path else 'root'
        self.package_functions[package].add(func_name)
        
        # Index methods
        if '.' in func_name:
            class_name, method_name = func_name.split('.', 1)
            self.method_index[method_name].append(func_name)
            self.class_index[class_name].add(method_name)
        
        # Index imports
        for imp in func_info.imports:
            self.import_index[func_info.file_path].add(imp)
            self.reverse_import_index[imp].add(func_info.file_path)
    
    def _build_similarity_index(self):
        """Build similarity relationships between functions"""
        function_names = list(self.function_index.keys())
        
        for i, func1 in enumerate(function_names):
            similar = []
            func1_info = self.function_index[func1]
            
            for j, func2 in enumerate(function_names[i+1:], i+1):
                func2_info = self.function_index[func2]
                similarity = self._calculate_function_similarity(func1_info, func2_info)
                
                if similarity > 0.7:  # High similarity threshold
                    similar.append(func2)
            
            self.similar_functions[func1] = similar
    
    def _calculate_function_similarity(self, func1: EnhancedFunctionInfo, func2: EnhancedFunctionInfo) -> float:
        """Calculate similarity between two functions"""
        # Name similarity (most important)
        name_sim = SequenceMatcher(None, func1.name.lower(), func2.name.lower()).ratio()
        
        # Parameter similarity
        param_sim = self._parameter_similarity(func1.signature, func2.signature)
        
        # Package/file similarity
        file_sim = 1.0 if func1.file_path == func2.file_path else 0.5 if func1.file_path.split('/')[0] == func2.file_path.split('/')[0] else 0.0
        
        # Weighted combination
        return (name_sim * 0.5 + param_sim * 0.3 + file_sim * 0.2)
    
    def _parameter_similarity(self, sig1: str, sig2: str) -> float:
        """Calculate parameter signature similarity"""
        # Extract parameters from signatures
        params1 = self._extract_parameters(sig1)
        params2 = self._extract_parameters(sig2)
        
        if not params1 and not params2:
            return 1.0
        if not params1 or not params2:
            return 0.0
        
        # Jaccard similarity of parameter sets
        common = len(set(params1) & set(params2))
        total = len(set(params1) | set(params2))
        
        return common / total if total > 0 else 0.0
    
    def _extract_parameters(self, signature: str) -> List[str]:
        """Extract parameter names from function signature"""
        # Simple regex to extract parameters
        match = re.search(r'\((.*?)\)', signature)
        if not match:
            return []
        
        params = match.group(1).split(',')
        return [p.strip().split(':')[0].strip() for p in params if p.strip() and p.strip() != 'self']

class ContextAwareResolver:
    """Advanced dependency resolver with context awareness and scoring"""
    
    def __init__(self, dependency_index: DependencyIndex):
        self.index = dependency_index
        self.fuzzy_threshold = 0.8
        self.context_weights = {
            'same_file': 0.4,
            'same_package': 0.2,
            'import_relationship': 0.3,
            'name_similarity': 0.1
        }
    
    def resolve_dependency(self, dep_name: str, context: EnhancedFunctionInfo) -> List[DependencyMatch]:
        """Resolve a dependency with multiple strategies and scoring"""
        matches = []
        
        # Strategy 1: Direct exact match - O(1)
        if dep_name in self.index.function_index:
            self.index.lookup_stats['hits'] += 1
            matches.append(DependencyMatch(
                target_function=dep_name,
                source_function=context.name,
                confidence=1.0,
                match_type='direct',
                reasoning='Exact function name match'
            ))
            return matches
        
        # Strategy 2: Constructor resolution - O(1)
        constructor_name = f"{dep_name}.__init__"
        if constructor_name in self.index.function_index:
            matches.append(DependencyMatch(
                target_function=constructor_name,
                source_function=context.name,
                confidence=0.95,
                match_type='constructor',
                reasoning=f'Constructor call: {dep_name}() -> {constructor_name}'
            ))
        
        # Strategy 3: Method resolution with context - O(1) lookup + O(k) scoring
        if '.' in dep_name:
            obj_name, method_name = dep_name.split('.', 1)
            possible_methods = self.index.method_index.get(method_name, [])
            
            for method_full_name in possible_methods:
                score = self._calculate_context_score(method_full_name, context)
                matches.append(DependencyMatch(
                    target_function=method_full_name,
                    source_function=context.name,
                    confidence=score,
                    match_type='method',
                    reasoning=f'Method resolution: {dep_name} -> {method_full_name}'
                ))
        
        # Strategy 4: Fuzzy matching - O(n) but only when needed
        if not matches or max(m.confidence for m in matches) < 0.7:
            self.index.lookup_stats['fuzzy_matches'] += 1
            fuzzy_matches = self._fuzzy_match(dep_name, context)
            matches.extend(fuzzy_matches)
        
        # Strategy 5: Import-based resolution
        import_matches = self._resolve_through_imports(dep_name, context)
        matches.extend(import_matches)
        
        if not matches:
            self.index.lookup_stats['misses'] += 1
        
        # Sort by confidence and return top candidates
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches[:5]  # Return top 5 matches
    
    def _calculate_context_score(self, target_func: str, context: EnhancedFunctionInfo) -> float:
        """Calculate context-aware confidence score"""
        if target_func not in self.index.function_index:
            return 0.0
        
        target_info = self.index.function_index[target_func]
        score = 0.0
        
        # Same file bonus
        if target_info.file_path == context.file_path:
            score += self.context_weights['same_file']
        
        # Same package bonus
        target_package = target_info.file_path.split('/')[0]
        context_package = context.file_path.split('/')[0]
        if target_package == context_package:
            score += self.context_weights['same_package']
        
        # Import relationship bonus
        if target_info.file_path in self.index.import_index.get(context.file_path, set()):
            score += self.context_weights['import_relationship']
        
        # Name similarity bonus
        name_similarity = SequenceMatcher(None, target_func.lower(), context.name.lower()).ratio()
        score += name_similarity * self.context_weights['name_similarity']
        
        return min(score, 0.95)  # Cap at 0.95 to reserve 1.0 for exact matches
    
    def _fuzzy_match(self, dep_name: str, context: EnhancedFunctionInfo) -> List[DependencyMatch]:
        """Perform fuzzy string matching"""
        matches = []
        
        for func_name in self.index.function_index.keys():
            similarity = SequenceMatcher(None, dep_name.lower(), func_name.lower()).ratio()
            
            if similarity >= self.fuzzy_threshold:
                context_score = self._calculate_context_score(func_name, context)
                combined_score = (similarity * 0.7 + context_score * 0.3)
                
                matches.append(DependencyMatch(
                    target_function=func_name,
                    source_function=context.name,
                    confidence=combined_score,
                    match_type='fuzzy',
                    reasoning=f'Fuzzy match: {dep_name} ~= {func_name} (sim: {similarity:.2f})'
                ))
        
        return matches
    
    def _resolve_through_imports(self, dep_name: str, context: EnhancedFunctionInfo) -> List[DependencyMatch]:
        """Resolve dependencies through import relationships"""
        matches = []
        
        # Check if dep_name matches any imported modules/functions
        context_imports = self.index.import_index.get(context.file_path, set())
        
        for imp in context_imports:
            if dep_name in imp or imp.endswith(f'.{dep_name}'):
                # Find functions in files that provide this import
                providing_files = self.index.reverse_import_index.get(imp, set())
                
                for file_path in providing_files:
                    file_functions = self.index.file_functions.get(file_path, set())
                    
                    for func_name in file_functions:
                        if dep_name in func_name:
                            matches.append(DependencyMatch(
                                target_function=func_name,
                                source_function=context.name,
                                confidence=0.8,
                                match_type='import',
                                reasoning=f'Import resolution: {dep_name} via {imp}'
                            ))
        
        return matches

class DataFlowAnalyzer(ast.NodeVisitor):
    """Analyzes data flow to improve type resolution"""
    
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.variable_types: Dict[str, Set[str]] = defaultdict(set)
        self.assignments: Dict[str, List[str]] = defaultdict(list)
        self.current_scope = []
        
    def analyze(self) -> Dict[str, Set[str]]:
        """Perform data flow analysis"""
        try:
            tree = ast.parse(self.source_code)
            self.visit(tree)
        except SyntaxError:
            pass  # Skip malformed code
        
        return dict(self.variable_types)
    
    def visit_Assign(self, node):
        """Track variable assignments"""
        # Handle: x = SomeClass()
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name):
                class_name = node.value.func.id
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        self.variable_types[var_name].add(class_name)
                        self.assignments[var_name].append(class_name)
        
        # Handle: x = y (type propagation)
        elif isinstance(node.value, ast.Name):
            source_var = node.value.id
            if source_var in self.variable_types:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_var = target.id
                        self.variable_types[target_var].update(self.variable_types[source_var])
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node):
        """Analyze function parameters and annotations"""
        # Track parameter types from annotations
        for arg in node.args.args:
            if arg.annotation:
                if isinstance(arg.annotation, ast.Name):
                    param_type = arg.annotation.id
                    self.variable_types[arg.arg].add(param_type)
        
        # Analyze function body
        old_scope = self.current_scope.copy()
        self.current_scope.append(node.name)
        self.generic_visit(node)
        self.current_scope = old_scope

class AdvancedCacheManager:
    """Advanced caching system with multiple cache levels"""
    
    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir or tempfile.gettempdir()) / 'enhanced_analyzer_cache'
        self.cache_dir.mkdir(exist_ok=True)
        
        # In-memory caches
        self.function_cache: Dict[str, EnhancedFunctionInfo] = {}
        self.dependency_cache: Dict[Tuple[str, str], List[DependencyMatch]] = {}
        self.analysis_cache: Dict[str, Dict[str, Any]] = {}
        
        # Cache statistics
        self.cache_stats = {
            'function_hits': 0,
            'function_misses': 0,
            'dependency_hits': 0,
            'dependency_misses': 0,
            'analysis_hits': 0,
            'analysis_misses': 0
        }
    
    @functools.lru_cache(maxsize=10000)
    def get_file_hash(self, file_path: str) -> str:
        """Get hash of file content for cache validation"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except (FileNotFoundError, PermissionError):
            return 'error'
    
    def get_cached_function_analysis(self, file_path: str) -> Optional[List[EnhancedFunctionInfo]]:
        """Get cached function analysis for a file"""
        cache_key = f"func_{hashlib.md5(file_path.encode()).hexdigest()}"
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            self.cache_stats['function_misses'] += 1
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            # Validate cache by file hash
            current_hash = self.get_file_hash(file_path)
            if data.get('file_hash') != current_hash:
                self.cache_stats['function_misses'] += 1
                return None
            
            self.cache_stats['function_hits'] += 1
            # Convert back to EnhancedFunctionInfo objects
            return self._deserialize_functions(data['functions'])
            
        except (json.JSONDecodeError, KeyError):
            self.cache_stats['function_misses'] += 1
            return None
    
    def cache_function_analysis(self, file_path: str, functions: List[EnhancedFunctionInfo]):
        """Cache function analysis results"""
        cache_key = f"func_{hashlib.md5(file_path.encode()).hexdigest()}"
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        data = {
            'file_path': file_path,
            'file_hash': self.get_file_hash(file_path),
            'timestamp': time.time(),
            'functions': self._serialize_functions(functions)
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Warning: Failed to cache analysis for {file_path}: {e}")
    
    def get_cached_dependencies(self, function_name: str, context_hash: str) -> Optional[List[DependencyMatch]]:
        """Get cached dependency analysis"""
        cache_key = (function_name, context_hash)
        
        if cache_key in self.dependency_cache:
            self.cache_stats['dependency_hits'] += 1
            return self.dependency_cache[cache_key]
        
        self.cache_stats['dependency_misses'] += 1
        return None
    
    def cache_dependencies(self, function_name: str, context_hash: str, dependencies: List[DependencyMatch]):
        """Cache dependency analysis results"""
        cache_key = (function_name, context_hash)
        self.dependency_cache[cache_key] = dependencies
        
        # Limit cache size
        if len(self.dependency_cache) > 50000:
            # Remove oldest 10% of entries
            items_to_remove = len(self.dependency_cache) // 10
            for _ in range(items_to_remove):
                self.dependency_cache.popitem()
    
    def _serialize_functions(self, functions: List[EnhancedFunctionInfo]) -> List[Dict]:
        """Serialize functions for caching"""
        result = []
        for func in functions:
            func_dict = {
                'name': func.name,
                'file_path': func.file_path,
                'line_number': func.line_number,
                'source_code': func.source_code,
                'dependencies': list(func.dependencies),
                'calls': list(func.calls),
                'imports': list(func.imports),
                'signature': func.signature,
                'docstring': func.docstring,
                'variable_types': {k: list(v) for k, v in func.variable_types.items()},
                'conditional_calls': list(func.conditional_calls),
                'loop_calls': list(func.loop_calls),
                'parameter_types': func.parameter_types,
                'return_type': func.return_type,
                'complexity_score': func.complexity_score
            }
            result.append(func_dict)
        return result
    
    def _deserialize_functions(self, functions_data: List[Dict]) -> List[EnhancedFunctionInfo]:
        """Deserialize functions from cache"""
        result = []
        for func_dict in functions_data:
            func = EnhancedFunctionInfo(
                name=func_dict['name'],
                file_path=func_dict['file_path'],
                line_number=func_dict['line_number'],
                source_code=func_dict['source_code'],
                dependencies=set(func_dict.get('dependencies', [])),
                calls=set(func_dict.get('calls', [])),
                imports=set(func_dict.get('imports', [])),
                signature=func_dict.get('signature', ''),
                docstring=func_dict.get('docstring', ''),
                variable_types={k: set(v) for k, v in func_dict.get('variable_types', {}).items()},
                conditional_calls=set(func_dict.get('conditional_calls', [])),
                loop_calls=set(func_dict.get('loop_calls', [])),
                parameter_types=func_dict.get('parameter_types', {}),
                return_type=func_dict.get('return_type'),
                complexity_score=func_dict.get('complexity_score', 0.0)
            )
            result.append(func)
        return result
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        total_function_requests = self.cache_stats['function_hits'] + self.cache_stats['function_misses']
        total_dependency_requests = self.cache_stats['dependency_hits'] + self.cache_stats['dependency_misses']
        total_analysis_requests = self.cache_stats['analysis_hits'] + self.cache_stats['analysis_misses']
        
        return {
            'function_cache': {
                'hit_rate': self.cache_stats['function_hits'] / max(1, total_function_requests),
                'hits': self.cache_stats['function_hits'],
                'misses': self.cache_stats['function_misses']
            },
            'dependency_cache': {
                'hit_rate': self.cache_stats['dependency_hits'] / max(1, total_dependency_requests),
                'hits': self.cache_stats['dependency_hits'],
                'misses': self.cache_stats['dependency_misses'],
                'size': len(self.dependency_cache)
            },
            'analysis_cache': {
                'hit_rate': self.cache_stats['analysis_hits'] / max(1, total_analysis_requests),
                'hits': self.cache_stats['analysis_hits'],
                'misses': self.cache_stats['analysis_misses']
            }
        }
    
    def clear_cache(self):
        """Clear all caches"""
        self.function_cache.clear()
        self.dependency_cache.clear()
        self.analysis_cache.clear()
        
        # Clear disk cache
        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                except Exception:
                    pass

class EnhancedPythonASTAnalyzer(_PythonASTAnalyzer):
    """Enhanced AST analyzer with data flow analysis"""
    
    def __init__(self, file_path: str, source: str):
        super().__init__(file_path, source)
        self.enhanced_functions: List[EnhancedFunctionInfo] = []
        self.data_flow_analyzer = DataFlowAnalyzer(source)
        self.variable_types = {}
    
    def analyze_enhanced(self) -> List[EnhancedFunctionInfo]:
        """Perform enhanced analysis with data flow"""
        # First run data flow analysis
        self.variable_types = self.data_flow_analyzer.analyze()
        
        # Then run standard AST analysis
        try:
            tree = ast.parse(self.source)
            self.visit(tree)
        except SyntaxError as e:
            print(f"Warning: Could not parse {self.file_path}: {e}")
        
        return self.enhanced_functions
    
    def visit_FunctionDef(self, node):
        """Enhanced function analysis"""
        func_info = self._extract_enhanced_function_info(node)
        self.enhanced_functions.append(func_info)
        self.generic_visit(node)
        
    def visit_AsyncFunctionDef(self, node):
        """Enhanced async function analysis"""
        func_info = self._extract_enhanced_function_info(node)
        self.enhanced_functions.append(func_info)
        self.generic_visit(node)
    
    def _extract_enhanced_function_info(self, node) -> EnhancedFunctionInfo:
        """Extract enhanced function information"""
        # Get basic info from parent class
        basic_info = self._extract_function_info(node)
        
        # Extract additional enhanced information
        variable_types = {}
        parameter_types = {}
        return_type = None
        complexity_score = self._calculate_complexity(node)
        
        # Extract parameter types from annotations
        for arg in node.args.args:
            if arg.annotation:
                if isinstance(arg.annotation, ast.Name):
                    parameter_types[arg.arg] = arg.annotation.id
        
        # Extract return type
        if node.returns:
            if isinstance(node.returns, ast.Name):
                return_type = node.returns.id
        
        # Get variable types from data flow analysis
        func_name = node.name
        if self.current_class:
            func_name = f"{self.current_class}.{func_name}"
        
        # Create enhanced function info
        enhanced_info = EnhancedFunctionInfo(
            name=basic_info.name,
            file_path=basic_info.file_path,
            line_number=basic_info.line_number,
            source_code=basic_info.source_code,
            dependencies=basic_info.dependencies,
            calls=basic_info.calls,
            imports=basic_info.imports,
            signature=basic_info.signature,
            docstring=basic_info.docstring,
            variable_types=variable_types,
            conditional_calls=set(),  # TODO: Implement conditional call detection
            loop_calls=set(),  # TODO: Implement loop call detection
            parameter_types=parameter_types,
            return_type=return_type,
            complexity_score=complexity_score
        )
        
        return enhanced_info
    
    def _calculate_complexity(self, node) -> float:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        
        return float(complexity)

class EnhancedPythonDependencyAnalyzer:
    """Enhanced dependency analyzer with all improvements"""
    
    def __init__(self, root_dir: str, max_functions_in_memory: int = 50000, cache_dir: str = None):
        self.root_dir = Path(root_dir).resolve()
        self.max_functions_in_memory = max_functions_in_memory
        
        # Enhanced components
        self.dependency_index = DependencyIndex()
        self.context_resolver = ContextAwareResolver(self.dependency_index)
        self.cache_manager = AdvancedCacheManager(cache_dir)
        
        # Function storage
        self.functions: Dict[str, EnhancedFunctionInfo] = {}
        self.classes: Dict[str, Dict[str, EnhancedFunctionInfo]] = {}
        self.imports: Dict[str, Set[str]] = defaultdict(set)
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Performance tracking
        self.performance_stats = {
            'files_analyzed': 0,
            'functions_found': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'analysis_time': 0.0
        }
    
    def analyze_codebase(self) -> None:
        """Enhanced codebase analysis with caching and parallel processing"""
        start_time = time.time()
        
        python_files = []
        for root, _, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(self.root_dir)
                    python_files.append(str(rel_path))
        
        print(f"Analyzing {len(python_files)} Python files with enhanced analyzer...")
        
        # Use parallel processing for large codebases
        if len(python_files) > 10:
            self._analyze_files_parallel_enhanced(python_files)
        else:
            self._analyze_files_sequential_enhanced(python_files)
        
        # Build indexes after all functions are collected
        print("Building enhanced dependency indexes...")
        self.dependency_index.build_indexes(self.functions)
        
        analysis_time = time.time() - start_time
        self.performance_stats['analysis_time'] = analysis_time
        self.performance_stats['files_analyzed'] = len(python_files)
        self.performance_stats['functions_found'] = len(self.functions)
        
        print(f"Enhanced analysis completed in {analysis_time:.2f}s")
        print(f"Found {len(self.functions)} functions in {len(python_files)} files")
        
        # Print cache statistics
        cache_stats = self.cache_manager.get_cache_stats()
        print(f"Cache performance: {cache_stats}")
    
    def analyze_file_enhanced(self, file_path: str) -> List[EnhancedFunctionInfo]:
        """Analyze a single file with enhanced features and caching"""
        full_path = self.root_dir / file_path
        
        # Try to get from cache first
        cached_functions = self.cache_manager.get_cached_function_analysis(str(full_path))
        if cached_functions is not None:
            self.performance_stats['cache_hits'] += 1
            return cached_functions
        
        self.performance_stats['cache_misses'] += 1
        
        try:
            # Check file size
            file_stats = full_path.stat()
            if file_stats.st_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                print(f"Warning: Skipping large file {file_path} ({file_stats.st_size} bytes)")
                return []
            
            with open(full_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            # Use enhanced analyzer
            analyzer = EnhancedPythonASTAnalyzer(file_path, source)
            functions = analyzer.analyze_enhanced()
            
            # Cache the results
            self.cache_manager.cache_function_analysis(str(full_path), functions)
            
            return functions
            
        except (SyntaxError, UnicodeDecodeError, FileNotFoundError, OSError) as e:
            print(f"Warning: Could not parse {file_path}: {e}")
            return []
    
    def _analyze_files_sequential_enhanced(self, python_files: List[str]) -> None:
        """Enhanced sequential analysis"""
        for file_path in python_files:
            functions = self.analyze_file_enhanced(file_path)
            self._store_functions_enhanced(functions)
    
    def _analyze_files_parallel_enhanced(self, python_files: List[str]) -> None:
        """Enhanced parallel analysis"""
        max_workers = min(8, len(python_files))
        total_files = len(python_files)
        processed_files = 0
        
        print(f"Using {max_workers} parallel workers for enhanced analysis...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.analyze_file_enhanced, file_path): file_path 
                for file_path in python_files
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    functions = future.result()
                    self._store_functions_enhanced(functions)
                    processed_files += 1
                    
                    if processed_files % 50 == 0 or processed_files == total_files:
                        progress = (processed_files / total_files) * 100
                        print(f"Progress: {processed_files}/{total_files} files analyzed ({progress:.1f}%)")
                        
                except Exception as e:
                    print(f"Warning: Error processing {file_path}: {e}")
                    processed_files += 1
    
    def _store_functions_enhanced(self, functions: List[EnhancedFunctionInfo]) -> None:
        """Store enhanced function information"""
        with self._lock:
            for func in functions:
                if len(self.functions) >= self.max_functions_in_memory:
                    print(f"Warning: Memory limit reached. {len(self.functions)} functions in memory.")
                
                self.functions[func.name] = func
                
                # Track classes
                if '.' in func.name:
                    class_name = func.name.split('.')[0]
                    if class_name not in self.classes:
                        self.classes[class_name] = {}
                    method_name = func.name.split('.')[1]
                    self.classes[class_name][method_name] = func
    
    def find_function_dependencies_enhanced(self, function_name: str, comprehensive: bool = True, min_confidence: float = 0.3, max_depth: int = 5) -> Dict[str, Any]:
        """Find dependencies using enhanced resolution
        
        Args:
            function_name: Target function to analyze
            comprehensive: If True, include all dependencies like original analyzer
            min_confidence: Minimum confidence threshold for matches
            max_depth: Maximum depth for transitive dependency analysis (1 = direct only, 2 = direct + one level)
        """
        if function_name not in self.functions:
            print(f"Function '{function_name}' not found in analyzed functions")
            print(f"Available functions: {list(self.functions.keys())[:10]}..." if self.functions else "None")
            return {
                'user_defined_order': [],
                'all_dependencies': set(),
                'total_calls': 0,
                'enhanced_matches': []
            }
        
        context = self.functions[function_name]
        context_hash = hashlib.md5(f"{function_name}{context.source_code}".encode()).hexdigest()[:16]
        
        # Check cache first
        cached_result = self.cache_manager.get_cached_dependencies(function_name, context_hash)
        if cached_result:
            print("Using cached dependency analysis")
            return self._build_result_from_matches(cached_result, function_name, comprehensive, min_confidence)
        
        all_matches = []
        visited_functions = {function_name}
        queue = [(function_name, 0)]  # (function_name, depth)
        
        print(f"Enhanced dependency analysis for {function_name}...")
        
        while queue:
            current_func, depth = queue.pop(0)
            
            if current_func not in self.functions or depth >= max_depth:
                continue
            
            func_info = self.functions[current_func]
            print(f"Analyzing dependencies for {current_func} (depth {depth}): {func_info.dependencies}")
            
            for dep in func_info.dependencies:
                # Use enhanced resolver
                dependency_matches = self.context_resolver.resolve_dependency(dep, func_info)
                
                for match in dependency_matches:
                    # Comprehensive mode: include more matches with lower confidence threshold
                    if comprehensive or match.confidence > min_confidence:
                        all_matches.append(match)
                        
                        if match.target_function not in visited_functions and depth < max_depth - 1:
                            visited_functions.add(match.target_function)
                            queue.append((match.target_function, depth + 1))
        
        # Cache the results
        self.cache_manager.cache_dependencies(function_name, context_hash, all_matches)
        
        return self._build_result_from_matches(all_matches, function_name, comprehensive, min_confidence)
    
    def _build_result_from_matches(self, matches: List[DependencyMatch], function_name: str, comprehensive: bool = False, min_confidence: float = 0.5) -> Dict[str, Any]:
        """Build result dictionary from dependency matches"""
        
        # Only filter out the main orchestration functions that aren't part of the direct pipeline
        pipeline_exclusions = {
            'main', 'run_basic_analysis', 'run_advanced_analysis', 
            'run_comprehensive_pipeline', 'compare_analysis_approaches',
            'generate_sample_data'
        }
        
        # Filter matches to exclude orchestration functions unless they're high confidence
        filtered_matches = []
        for match in matches:
            if match.target_function in pipeline_exclusions:
                # Only include if very high confidence (direct call/import)
                if match.confidence >= 0.9:
                    filtered_matches.append(match)
            else:
                filtered_matches.append(match)
        
        # Get unique functions for topological sort
        unique_functions = list(set([match.target_function for match in filtered_matches if match.target_function in self.functions]))
        
        # Add the target function itself to the dependencies (like original analyzer)
        if function_name in self.functions and function_name not in unique_functions:
            unique_functions.append(function_name)
        
        # Perform topological sort
        ordered_deps = self._topological_sort_enhanced(unique_functions)
        
        # Get detailed information
        detailed_dependencies = []
        for dep_name in ordered_deps:
            if dep_name in self.functions:
                func_info = self.functions[dep_name]
                detailed_dependencies.append({
                    'name': func_info.name,
                    'file_path': func_info.file_path,
                    'line_number': func_info.line_number,
                    'signature': func_info.signature,
                    'source_code': func_info.source_code,
                    'docstring': func_info.docstring,
                    'complexity_score': func_info.complexity_score,
                    'parameter_types': func_info.parameter_types,
                    'return_type': func_info.return_type
                })
        
        # Collect enhanced match information
        enhanced_matches = []
        for match in filtered_matches:
            enhanced_matches.append({
                'target': match.target_function,
                'source': match.source_function,
                'confidence': match.confidence,
                'type': match.match_type,
                'reasoning': match.reasoning
            })
        
        return {
            'dependency_order': ordered_deps,  # Changed from user_defined_order
            'user_defined_order': ordered_deps,  # Keep for compatibility
            'all_dependencies': set([match.target_function for match in filtered_matches]),
            'total_calls': len(set([match.target_function for match in filtered_matches])),
            'total_dependencies': len(ordered_deps),  # Added for compatibility
            'detailed_dependencies': detailed_dependencies,
            'enhanced_matches': enhanced_matches,
            'analysis_method': 'enhanced_ast_based',
            'found_function_name': function_name,
            'language': 'python',
            'raw_calls': sorted(list(set([match.target_function for match in filtered_matches])))  # Added for compatibility
        }
    
    def _topological_sort_enhanced(self, func_names: List[str]) -> List[str]:
        """Enhanced topological sorting with better cycle detection"""
        in_degree = {name: 0 for name in func_names}
        graph = {name: [] for name in func_names}
        
        # Build dependency graph
        for func_name in func_names:
            if func_name in self.functions:
                func_info = self.functions[func_name]
                for dep in func_info.dependencies:
                    # Resolve each dependency to get actual target
                    matches = self.context_resolver.resolve_dependency(dep, func_info)
                    for match in matches:
                        if match.target_function in func_names and match.confidence > 0.3:  # Lower threshold for comprehensive analysis
                            graph[match.target_function].append(func_name)
                            in_degree[func_name] += 1
                            break  # Use only the best match
        
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
        
        # Check for cycles
        if len(result) < len(func_names):
            missing_funcs = set(func_names) - set(result)
            print(f"Warning: Potential circular dependencies detected: {missing_funcs}")
            # Add missing functions at the end
            result.extend(missing_funcs)
        
        return result
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics"""
        cache_stats = self.cache_manager.get_cache_stats()
        lookup_stats = self.dependency_index.lookup_stats
        
        return {
            'performance': self.performance_stats,
            'cache': cache_stats,
            'lookup': lookup_stats,
            'functions': {
                'total': len(self.functions),
                'classes': len(self.classes),
                'average_complexity': sum(f.complexity_score for f in self.functions.values()) / max(1, len(self.functions))
            }
        }


def main_enhanced():
    """Enhanced main function with new features"""
    parser = argparse.ArgumentParser(
        description='Enhanced Python codebase dependency analyzer with O(1) lookups and context awareness',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Enhanced Features:
- O(1) dependency lookups with indexed resolution
- Context-aware dependency scoring
- Advanced caching with persistence
- Data flow analysis for better type resolution  
- Fuzzy string matching for partial matches
- Comprehensive performance statistics

Examples:
  python enhanced_analyzer.py mypackage.whl function_snippet.txt
  python enhanced_analyzer.py codebase.zip snippet.py --cache-dir ./cache
        """
    )
    
    parser.add_argument('codebase', help='Path to .whl or .zip file containing the codebase')
    parser.add_argument('snippet', help='Path to text file containing function snippet')
    parser.add_argument('--output', '-o', help='Output file for results (default: stdout)')
    parser.add_argument('--format', choices=['json', 'text'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--cache-dir', help='Directory for persistent caching')
    parser.add_argument('--clear-cache', action='store_true', help='Clear cache before analysis')
    parser.add_argument('--stats', action='store_true', help='Show detailed performance statistics')
    parser.add_argument('--comprehensive', action='store_true', 
                       help='Enable comprehensive mode (like original analyzer - see everything)')
    parser.add_argument('--min-confidence', type=float, default=0.5,
                       help='Minimum confidence threshold for dependency matches (default: 0.5)')
    
    args = parser.parse_args()
    
    # Validate inputs (same as original)
    if not os.path.exists(args.codebase):
        print(f"Error: Codebase file not found: {args.codebase}", file=sys.stderr)
        return 1
        
    if not os.path.exists(args.snippet):
        print(f"Error: Function snippet file not found: {args.snippet}", file=sys.stderr)
        return 1
    
    codebase_ext = Path(args.codebase).suffix.lower()
    if codebase_ext not in ['.zip', '.whl']:
        print(f"Error: Unsupported codebase file type: {codebase_ext}", file=sys.stderr)
        return 1
    
    # Create enhanced analyzer
    from code_analyzer import CodebaseDependencyAnalyzer
    
    class EnhancedCodebaseDependencyAnalyzer(CodebaseDependencyAnalyzer):
        """Enhanced version of the main analyzer"""
        
        def _analyze_dependencies(self, function_info: Dict[str, Any]) -> Dict[str, Any]:
            """Use enhanced analyzer for dependencies"""
            analyzer = EnhancedPythonDependencyAnalyzer(
                self.extracted_dir, 
                cache_dir=args.cache_dir
            )
            
            if args.clear_cache:
                analyzer.cache_manager.clear_cache()
                print("Cache cleared")
            
            analyzer.analyze_codebase()
            
            function_name = function_info['function_name']
            
            # Try different function name variants
            possible_names = [function_name]
            for class_name in analyzer.classes.keys():
                possible_names.append(f"{class_name}.{function_name}")
            
            found_function_name = None
            for name in possible_names:
                if name in analyzer.functions:
                    found_function_name = name
                    break
            
            if not found_function_name:
                print(f"Available functions: {list(analyzer.functions.keys())[:20]}...")
                result = {
                    'dependency_order': [],
                    'detailed_dependencies': [],
                    'total_dependencies': 0,
                    'analysis_method': 'enhanced_function_not_found',
                    'error': f'Function {function_name} not found in analyzed functions',
                    'enhanced_matches': [],
                    'stats': analyzer.get_analysis_stats()
                }
            else:
                dependencies_result = analyzer.find_function_dependencies_enhanced(found_function_name, comprehensive=True, min_confidence=0.3)
                dependencies_result['stats'] = analyzer.get_analysis_stats()
                result = dependencies_result
            
            return result
    
    # Run enhanced analysis
    analyzer = EnhancedCodebaseDependencyAnalyzer(args.codebase, args.snippet)
    result = analyzer.run()
    
    # Add performance stats if requested
    if args.stats and 'dependencies' in result and 'stats' in result['dependencies']:
        stats = result['dependencies']['stats']
        print("\n" + "="*50)
        print("ENHANCED ANALYSIS PERFORMANCE STATISTICS")
        print("="*50)
        print(f"Files analyzed: {stats['performance']['files_analyzed']}")
        print(f"Functions found: {stats['performance']['functions_found']}")
        print(f"Analysis time: {stats['performance']['analysis_time']:.2f}s")
        print(f"Cache hit rate: {stats['cache']['function_cache']['hit_rate']:.1%}")
        print(f"Lookup hit rate: {stats['lookup']['hits']/(stats['lookup']['hits'] + stats['lookup']['misses']):.1%}")
        print(f"Average function complexity: {stats['functions']['average_complexity']:.2f}")
        print("="*50)
    
    # Format and output results (same as original)
    if args.format == 'json':
        output = json.dumps(result, indent=2, default=str)
    else:
        output = _format_enhanced_text_output(result)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Enhanced results written to: {args.output}")
    else:
        try:
            print(output)
        except UnicodeEncodeError:
            ascii_safe_output = output.encode('ascii', errors='replace').decode('ascii')
            print(ascii_safe_output)
    
    return 0 if result.get('success') else 1


def _format_enhanced_text_output(result: Dict[str, Any]) -> str:
    """Format enhanced results as human-readable text"""
    from code_analyzer import _format_text_output
    
    # Use original formatting as base
    output_lines = _format_text_output(result).split('\n')
    
    # Add enhanced information
    if 'dependencies' in result and 'enhanced_matches' in result['dependencies']:
        enhanced_matches = result['dependencies']['enhanced_matches']
        
        if enhanced_matches:
            output_lines.append("\nEnhanced Dependency Matches:")
            output_lines.append("-" * 35)
            
            for match in enhanced_matches[:10]:  # Show top 10 matches
                output_lines.append(f"Target: {match['target']}")
                output_lines.append(f"  Confidence: {match['confidence']:.2f}")
                output_lines.append(f"  Type: {match['type']}")
                output_lines.append(f"  Reasoning: {match['reasoning']}")
                output_lines.append("")
    
    return '\n'.join(output_lines)


if __name__ == '__main__':
    sys.exit(main_enhanced())
