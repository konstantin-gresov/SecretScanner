import os
import json
import re
import ast
import math
import configparser
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple, Any
from colorama import init, Fore, Style
import pickle
from collections import Counter
import javalang
from javalang.tree import (
    LocalVariableDeclaration,
    FieldDeclaration,
    Assignment,
    MethodInvocation,
    Literal,
    MemberReference,
    ArrayInitializer,
    ClassCreator
)
from javalang.ast import Node
from javalang.parser import JavaSyntaxError

init(autoreset=True)


@dataclass
class Secret:
    """
    Data class representing a found secret.
    Attributes:
        secret_type (str): Type of secret (e.g., 'Base64 String', 'ast_secret').
        filename (str): Path to the file where secret was found.
        line_number (int): Line number in the file.
        plain_string (str): Full line content.
        matched_part (str): The exact substring that matched.
        start (int): Start index of match in the line.
        end (int): End index of match.
        criticality (str): Risk level (low, medium, high, critical).
        recommendation (str): Recommendation for handling the secret.
        analyzer (str): Which analyzer found it ('regex', 'ast', 'entropy', 'java_ast').
    """
    secret_type: str
    filename: str
    line_number: int
    plain_string: str
    matched_part: str
    start: int
    end: int
    criticality: str
    recommendation: str
    analyzer: str = "regex"

    def to_dict(self) -> Dict[str, Any]:
        """Convert Secret object to a dictionary for JSON serialization."""
        return {
            "type": self.secret_type,
            "filename": self.filename,
            "line_number": self.line_number,
            "details": {
                "plain_string": self.plain_string,
                "matched_part": self.matched_part,
                "start": self.start,
                "end": self.end,
                "criticality": self.criticality,
                "recommendation": self.recommendation,
                "analyzer": self.analyzer
            }
        }


class Config:
    """
    Handles configuration loading from settings.ini and command-line arguments.
    """

    def __init__(self):
        self.config = self._read_settings()
        self.args = self._parse_args()

    def _read_settings(self) -> configparser.ConfigParser:
        """Read settings.ini file."""
        config = configparser.ConfigParser()
        config.read("settings.ini")
        return config

    def _parse_args(self) -> argparse.Namespace:
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(description="Secret Scanner")
        parser.add_argument('projectdirectory', type=str, help="Project directory")
        parser.add_argument('-r', '--rules', type=str,
                            default=self._get_default('json_settings', 'rules_regex'),
                            help='JSON file with regular expressions')
        parser.add_argument('-i', '--ignore', type=str,
                            default=self._get_default('json_settings', 'rules_ignore'),
                            help='JSON file with files/extensions/directories to ignore')
        parser.add_argument('-a', '--ast', action='store_true',
                            help='Use AST-parsing analysis')
        parser.add_argument('-e', '--entropy', action='store_true',
                            help='Use entropy analysis (helpful for base64-like secrets)')
        parser.add_argument('-s', '--save', type=str,
                            default=self._get_default('json_settings', 'default_result_filename'),
                            help='Filename for report')
        parser.add_argument('--html', action='store_true',
                            help='Generate HTML report')
        parser.add_argument('--no-cache', action='store_true',
                            help='Disable caching of scan results')
        return parser.parse_args()

    def _get_default(self, section: str, key: str) -> str:
        """Get default value from config file, return empty string if not found."""
        try:
            return self.config[section][key]
        except (KeyError, configparser.NoSectionError, configparser.NoOptionError):
            return ""

    @property
    def project_dir(self) -> str:
        return self.args.projectdirectory

    @property
    def rules_file(self) -> str:
        return self.args.rules

    @property
    def ignore_file(self) -> str:
        return self.args.ignore

    @property
    def use_ast(self) -> bool:
        return self.args.ast

    @property
    def use_entropy(self) -> bool:
        return self.args.entropy

    @property
    def result_filename(self) -> str:
        return self.args.save

    @property
    def need_html(self) -> bool:
        return self.args.html

    @property
    def no_cache(self) -> bool:
        return self.args.no_cache

    def get_ast_keywords(self) -> List[str]:
        """
        Load AST keywords from ast_keywords.json or return default list.
        Returns:
            List of sensitive keywords for AST analysis.
        """
        try:
            with open(self.config["json_settings"]["ast_keywords"], encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data.get("keywords", [])
                elif isinstance(data, list):
                    return data
                else:
                    return []
        except FileNotFoundError:
            return ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
                    "auth", "authorization", "credential", "private_key", "access_key"]


class IgnoreRules:
    """
    Manages ignore rules (files, extensions, directories) loaded from a JSON file.
    """

    def __init__(self, ignore_file: str):
        self.ignore_files: Set[str] = set()
        self.ignore_extensions: Set[str] = set()
        self.ignore_dirs: Set[str] = set()
        self._load(ignore_file)

    def _load(self, ignore_file: str) -> None:
        """Load ignore rules from JSON file."""
        try:
            with open(ignore_file, encoding="utf-8") as f:
                data = json.load(f)
                ignore = data.get("ignore", {})
                self.ignore_files = set(ignore.get("files", []))
                self.ignore_extensions = set(ignore.get("extensions", []))
                self.ignore_dirs = set(ignore.get("dirs", []))
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"{Fore.YELLOW}Warning: Could not load ignore file {ignore_file}: {e}{Style.RESET_ALL}")

    def should_ignore_file(self, filename: str) -> bool:
        """
        Check if a file should be ignored based on its name or extension.
        Args:
            filename: Full path to the file.
        Returns:
            True if file should be ignored, False otherwise.
        """
        base = os.path.basename(filename)
        if base in self.ignore_files:
            return True
        ext = os.path.splitext(base)[1].lower()
        return ext in self.ignore_extensions

    def should_ignore_dir(self, dirname: str) -> bool:
        """
        Check if a directory should be ignored.
        Args:
            dirname: Directory name (without path).
        Returns:
            True if directory should be ignored, False otherwise.
        """
        return os.path.basename(dirname) in self.ignore_dirs


class RegexRules:
    """
    Loads and compiles regular expression rules from a JSON file.
    """

    def __init__(self, rules_file: str):
        self.patterns: Dict[str, Dict] = {}
        self._load(rules_file)

    def _load(self, rules_file: str) -> None:
        """Load regex patterns from JSON and compile them."""
        try:
            with open(rules_file, encoding="utf-8") as f:
                data = json.load(f)
                patterns = data.get("patterns", {})
                for name, rule in patterns.items():
                    rule["compiled"] = re.compile(rule["regex"])
                    self.patterns[name] = rule
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            raise RuntimeError(f"Failed to load rules from {rules_file}: {e}")

    def check_string(self, text: str) -> Optional[Tuple[str, re.Match, Dict]]:
        """
        Check a string against all compiled patterns.
        Args:
            text: The string to check.
        Returns:
            Tuple (rule_name, match_object, rule_dict) if match found, else None.
        """
        for name, rule in self.patterns.items():
            match = rule["compiled"].search(text)
            if match:
                return name, match, rule
        return None


class EntropyAnalyzer:
    """
    Analyzer that detects high-entropy strings (potential secrets like base64).
    """

    def __init__(self, threshold: float = 4.5, min_length: int = 12):
        self.threshold = threshold
        self.min_length = min_length

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        counter = Counter(data)
        entropy = 0.0
        for count in counter.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def analyze(self, filepath: str, lines: List[str]) -> List[Secret]:
        """
        Analyze lines of a file for high-entropy strings.
        Args:
            filepath: Path to the file (for reporting).
            lines: List of lines from the file.
        Returns:
            List of Secret objects for strings exceeding entropy threshold.
        """
        secrets = []
        for line_num, line in enumerate(lines, start=1):
            line = line.rstrip('\n')
            if len(line) < self.min_length:
                continue
            ent = self.shannon_entropy(line)
            if ent > self.threshold:
                criticality = "warning"
                secret = Secret(
                    secret_type="entropy_secret",
                    filename=filepath,
                    line_number=line_num,
                    plain_string=line,
                    matched_part=line,
                    start=0,
                    end=len(line),
                    criticality=criticality,
                    recommendation="Check if this is a randomly generated secret (e.g., token, key).",
                    analyzer="entropy"
                )
                secrets.append(secret)
        return secrets


class ASTAnalyzer:
    """
    AST-based analyzer for Python files.
    Detects assignments of string literals to sensitive variable names.
    """

    def __init__(self, keywords: List[str]):
        self.keywords = [kw.lower() for kw in keywords]

    def analyze(self, filepath: str, content: str) -> List[Secret]:
        """
        Analyze Python file content using AST.
        Args:
            filepath: Path to the file (must end with .py).
            content: Full file content as string.
        Returns:
            List of Secret objects found.
        """
        if not filepath.endswith('.py'):
            return []
        secrets = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        for node in ast.walk(tree):
            # Assignment: x = "secret"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    targets = self._flatten_targets(target)
                    for t in targets:
                        if isinstance(t, ast.Name) and self._is_sensitive_name(t.id):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                secret = self._create_secret(filepath, node.value, node.lineno,
                                                             f"Sensitive variable '{t.id}'")
                                secrets.append(secret)
                        elif isinstance(t, ast.Attribute) and self._is_sensitive_name(t.attr):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                secret = self._create_secret(filepath, node.value, node.lineno,
                                                             f"Sensitive attribute '{t.attr}'")
                                secrets.append(secret)
            # Annotated assignment: x: str = "secret"
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and self._is_sensitive_name(node.target.id):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        secret = self._create_secret(filepath, node.value, node.lineno,
                                                     f"Sensitive annotated variable '{node.target.id}'")
                        secrets.append(secret)
                elif isinstance(node.target, ast.Attribute) and self._is_sensitive_name(node.target.attr):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        secret = self._create_secret(filepath, node.value, node.lineno,
                                                     f"Sensitive annotated attribute '{node.target.attr}'")
                        secrets.append(secret)
            # Dictionary key: {"password": "secret"}
            elif isinstance(node, ast.Dict):
                for key, val in zip(node.keys, node.values):
                    if key and isinstance(key, ast.Constant) and isinstance(key.value, str):
                        if self._is_sensitive_name(key.value):
                            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                                secret = self._create_secret(filepath, val, key.lineno,
                                                             f"Sensitive dict key '{key.value}'")
                                secrets.append(secret)
            # Function call argument: func(password="secret")
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg and self._is_sensitive_name(kw.arg):
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            secret = self._create_secret(filepath, kw.value, kw.value.lineno,
                                                         f"Sensitive argument '{kw.arg}'")
                            secrets.append(secret)

        return secrets

    def _flatten_targets(self, target):
        """Flatten tuple/list assignment targets into individual names."""
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                yield from self._flatten_targets(elt)
        else:
            yield target

    def _is_sensitive_name(self, name: str) -> bool:
        """Check if a name contains any sensitive keyword (case-insensitive)."""
        name_lower = name.lower()
        return any(kw in name_lower for kw in self.keywords)

    def _create_secret(self, filepath: str, node: ast.Constant, lineno: int, reason: str) -> Secret:
        """Create a Secret object from AST node information."""
        return Secret(
            secret_type="ast_secret",
            filename=filepath,
            line_number=lineno,
            plain_string=node.value,
            matched_part=node.value,
            start=0,
            end=len(node.value),
            criticality="medium",
            recommendation=f"Potential hardcoded secret detected: {reason}",
            analyzer="ast"
        )


class JavaASTAnalyzer:
    """
    AST-based analyzer for Java files.
    Detects assignments of string literals to sensitive variable/field names,
    and sensitive arguments in method/constructor calls.
    """

    def __init__(self, keywords: List[str]):
        self.keywords = [kw.lower() for kw in keywords]

    def analyze(self, filepath: str, content: str) -> List[Secret]:
        """
        Analyze Java file content using javalang AST.
        Args:
            filepath: Path to the file (must end with .java).
            content: Full file content as string.
        Returns:
            List of Secret objects found.
        """
        if not filepath.endswith('.java'):
            return []
        try:
            tree = javalang.parse.parse(content)
        except JavaSyntaxError:
            return []

        secrets = []
        for node in self._walk(tree):
            self._process_node(node, filepath, secrets)
        return secrets

    def _walk(self, node):
        """Recursively yield all nodes in the AST."""
        yield node
        for child in node.children:
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, Node):
                        yield from self._walk(item)
            elif isinstance(child, Node):
                yield from self._walk(child)

    def _process_node(self, node, filepath, secrets):
        """Process a single AST node."""
        # Variable/field declarations
        if isinstance(node, (LocalVariableDeclaration, FieldDeclaration)):
            for declarator in node.declarators:
                name = declarator.name
                if self._is_sensitive_name(name):
                    init = declarator.initializer
                    if init:
                        self._check_initializer(init, filepath, secrets, context=f"variable '{name}'", node=node)

        # Assignment statements
        elif isinstance(node, Assignment):
            if node.type != '=':
                return
            left = node.expressionl
            right = node.value
            if isinstance(right, Literal) and self._is_string_literal(right.value):
                value_str = right.value
                line = self._get_line(right, node)

                if isinstance(left, MemberReference) and self._is_sensitive_name(left.member):
                    desc = f"Sensitive variable/field '{left.member}' in assignment"
                    secrets.append(self._create_secret(filepath, value_str, line, desc))

        # Method invocations
        elif isinstance(node, MethodInvocation):
            if self._is_sensitive_name(node.member):
                for arg in node.arguments:
                    if isinstance(arg, Literal) and self._is_string_literal(arg.value):
                        line = self._get_line(arg, node)
                        desc = f"Sensitive argument in call to '{node.member}'"
                        secrets.append(self._create_secret(filepath, arg.value, line, desc))

        # Constructor calls (new SomeClass(...))
        elif isinstance(node, ClassCreator):
            class_name = node.type.name
            if self._is_sensitive_name(class_name):
                for arg in node.arguments:
                    if isinstance(arg, Literal) and self._is_string_literal(arg.value):
                        line = self._get_line(arg, node)
                        desc = f"Sensitive argument in constructor of '{class_name}'"
                        secrets.append(self._create_secret(filepath, arg.value, line, desc))

    def _check_initializer(self, init, filepath, secrets, context, node):
        """Check an initializer for string literals."""
        if isinstance(init, Literal) and self._is_string_literal(init.value):
            line = self._get_line(init, node)
            desc = f"Sensitive {context}"
            secrets.append(self._create_secret(filepath, init.value, line, desc))
        elif isinstance(init, ArrayInitializer):
            for elem in init.initializers:
                if isinstance(elem, Literal) and self._is_string_literal(elem.value):
                    line = self._get_line(elem, init)
                    desc = f"Sensitive array element for {context}"
                    secrets.append(self._create_secret(filepath, elem.value, line, desc))

    @staticmethod
    def _get_line(target_node, fallback_node) -> int:
        """Get line number from node position, fallback to another node if necessary."""
        if target_node.position:
            return target_node.position.line
        if fallback_node.position:
            return fallback_node.position.line
        return 0

    def _is_string_literal(self, value: str) -> bool:
        """Heuristic to determine if a literal is a string (not number, boolean, null)."""
        v_low = value.lower()
        if v_low in ('null', 'true', 'false'):
            return False
        tmp = value.lstrip('-').replace('_', '')
        if tmp.replace('.', '', 1).isdigit():
            return False
        return True

    def _is_sensitive_name(self, name: str) -> bool:
        """Check if a name contains any sensitive keyword (case-insensitive)."""
        name_low = name.lower()
        return any(kw in name_low for kw in self.keywords)

    def _create_secret(self, filepath, value, line, desc):
        """Create a Secret object."""
        return Secret(
            secret_type="java_ast_secret",
            filename=filepath,
            line_number=line,
            plain_string=value,
            matched_part=value,
            start=0,
            end=len(value),
            criticality="medium",
            recommendation=desc,
            analyzer="java_ast"
        )


class ScanCache:
    """
    Persistent cache for scan results to avoid re-scanning unchanged files.
    """

    def __init__(self, cache_file: str = ".secretscanner_cache.pkl"):
        self.cache_file = cache_file
        self.cache = self._load()

    def _load(self) -> Dict:
        """Load cache from disk."""
        try:
            with open(self.cache_file, "rb") as f:
                return pickle.load(f)
        except (FileNotFoundError, pickle.PickleError, EOFError):
            return {}

    def _save(self) -> None:
        """Save cache to disk."""
        try:
            with open(self.cache_file, "wb") as f:
                pickle.dump(self.cache, f)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to write cache: {e}{Style.RESET_ALL}")

    def get(self, filepath: str) -> Optional[List[Secret]]:
        """
        Retrieve cached secrets for a file if it hasn't changed.
        Args:
            filepath: Path to the file.
        Returns:
            List of Secret objects if cache hit and file unchanged, else None.
        """
        stat = os.stat(filepath)
        current_mtime = stat.st_mtime
        current_size = stat.st_size
        entry = self.cache.get(filepath)
        if entry and entry['mtime'] == current_mtime and entry['size'] == current_size:
            return entry['secrets']
        return None

    def put(self, filepath: str, secrets: List[Secret]) -> None:
        """Store secrets for a file in cache."""
        stat = os.stat(filepath)
        self.cache[filepath] = {
            'mtime': stat.st_mtime,
            'size': stat.st_size,
            'secrets': secrets
        }
        self._save()


class CriticalityEnhancer:
    """
    Enhances criticality of secrets found in sensitive directories.
    """

    def __init__(self, config_file: str = "rules/criticality_paths.json"):
        self.sensitive_paths = self._load_sensitive_paths(config_file)

    def _load_sensitive_paths(self, config_file: str) -> List[str]:
        """Load list of directory names that should trigger criticality increase."""
        try:
            with open(config_file, encoding="utf-8") as f:
                paths = json.load(f)
                if isinstance(paths, list):
                    return paths
                else:
                    print(f"{Fore.YELLOW}Warning: {config_file} should contain a list. Using defaults.{Style.RESET_ALL}")
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        # Default sensitive paths
        return [".env", "env", "config", "configuration", "secret", "secrets",
                "credential", "credentials", "key", "keys", "token", "tokens",
                "auth", "private"]

    def enhance(self, secrets: List[Secret]) -> List[Secret]:
        """
        Increase criticality for secrets whose file path contains any sensitive directory.
        Args:
            secrets: List of Secret objects.
        Returns:
            Modified list with updated criticalities.
        """
        enhanced = []
        for s in secrets:
            path_parts = s.filename.split(os.sep)
            # Check if any part of the path (directory name) is in sensitive_paths
            if any(part in self.sensitive_paths for part in path_parts):
                # Increase criticality: low -> medium, medium -> high, high -> critical
                if s.criticality.lower() == "low":
                    s.criticality = "medium"
                elif s.criticality.lower() == "medium":
                    s.criticality = "high"
                elif s.criticality.lower() == "high":
                    s.criticality = "critical"
                # critical remains critical
            enhanced.append(s)
        return enhanced


class HTMLReportGenerator:
    @staticmethod
    def generate(secrets: List[Secret], output_file: str) -> None:
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Scanner Report</title>
    <style>
        * {box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background: #f5f7fa;
            color: #333;
        }
        h1 { 
            color: #2c3e50; 
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 3px solid #3498db;
        }
        .summary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .summary strong { font-size: 1.5em; }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-top: 20px;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        th, td { 
            border: 1px solid #e1e5eb; 
            padding: 12px 15px; 
            text-align: left; 
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            cursor: pointer;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        th:hover { background: linear-gradient(135deg, #5a6fd6 0%, #6a4190 100%); }
        tr:nth-child(even) { background-color: #f8f9fc; }
        tr:hover { background-color: #e8ecf3; }
        .critical { background-color: #ffebee !important; border-left: 4px solid #e74c3c; }
        .high { background-color: #fff3e0 !important; border-left: 4px solid #f39c12; }
        .medium { background-color: #fff9c4 !important; border-left: 4px solid #f1c40f; }
        .low { background-color: #e3f2fd !important; border-left: 4px solid #3498db; }
        .filter-container {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .filter-input { 
            padding: 10px 15px; 
            width: 300px; 
            border: 2px solid #ddd;
            border-radius: 25px;
            font-size: 14px;
            outline: none;
        }
        .filter-input:focus { border-color: #667eea; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: #e74c3c; color: white; }
        .badge-high { background: #f39c12; color: white; }
        .badge-medium { background: #f1c40f; color: #333; }
        .badge-low { background: #3498db; color: white; }
        code {
            background: #2c3e50;
            color: #2ecc71;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        .analyzer-tag {
            background: #ecf0f1;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            color: #7f8c8d;
        }
        footer {
            margin-top: 30px;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <h1>🔐 Secret Scanner Report</h1>
    <div class="summary">
        <p>Found <strong>$count</strong> potential secrets</p>
    </div>
    <div class="filter-container">
        <input type="text" id="filter" class="filter-input" placeholder="🔍 Filter results..." onkeyup="filterTable()">
    </div>
    <table id="secrets-table">
        <thead>
            <tr>
                <th onclick="sortTable(0)">Type</th>
                <th onclick="sortTable(1)">Criticality</th>
                <th onclick="sortTable(2)">File</th>
                <th onclick="sortTable(3)">Line</th>
                <th onclick="sortTable(4)">Secret</th>
                <th onclick="sortTable(5)">Analyzer</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
$rows
        </tbody>
    </table>
    <footer>
        <p>Generated by SecScanner | $timestamp</p>
    </footer>
    <script>
        function filterTable() {
            var input = document.getElementById("filter");
            var filter = input.value.toUpperCase();
            var table = document.getElementById("secrets-table");
            var rows = table.getElementsByTagName("tr");
            for (var i = 1; i < rows.length; i++) {
                var cells = rows[i].getElementsByTagName("td");
                var found = false;
                for (var j = 0; j < cells.length; j++) {
                    if (cells[j] && cells[j].innerText.toUpperCase().indexOf(filter) > -1) {
                        found = true;
                        break;
                    }
                }
                rows[i].style.display = found ? "" : "none";
            }
        }
        function sortTable(n) {
            var table = document.getElementById("secrets-table");
            var rows = table.rows, switching = true, i, x, y, shouldSwitch, dir = "asc", switchcount = 0;
            while (switching) {
                switching = false;
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i + 1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    } else {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else {
                    if (switchcount == 0 && dir == "asc") {
                        dir = "desc";
                        switching = true;
                    }
                }
            }
        }
    </script>
</body>
</html>"""
        
        rows_html = []
        for s in secrets:
            criticality_class = s.criticality.lower()
            if criticality_class == "warning":
                row_class = ""
                badge_html = f'<span class="badge">{s.criticality}</span>'
            else:
                row_class = f'class="{criticality_class}"'
                badge_html = f'<span class="badge badge-{criticality_class}">{s.criticality}</span>'

            secret_display = f"<code>{s.matched_part[:60]}{'...' if len(s.matched_part) > 60 else ''}</code>"
            row = f"""            <tr {row_class}>
                <td>{s.secret_type}</td>
                <td>{badge_html}</td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">{s.filename}</td>
                <td>{s.line_number}</td>
                <td style="font-family: monospace;">{secret_display}</td>
                <td><span class="analyzer-tag">{s.analyzer}</span></td>
                <td>{s.recommendation}</td>
            </tr>"""
            rows_html.append(row)
        
        from datetime import datetime
        from string import Template  # уже импортирован в начале файла, но для ясности
        template = Template(html_template)
        full_html = template.substitute(
            count=len(secrets),
            rows="\n".join(rows_html),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(full_html)
            print(f"{Fore.GREEN}HTML report generated: {output_file}{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}Error saving HTML report: {e}{Style.RESET_ALL}")


class FileScanner:
    """Walks a directory and returns files not matching ignore rules."""

    def __init__(self, root_dir: str, ignore_rules: IgnoreRules):
        self.root_dir = root_dir
        self.ignore_rules = ignore_rules

    def get_files(self) -> List[str]:
        """Return list of file paths that should be scanned."""
        files = []
        for address, dirs, filenames in os.walk(self.root_dir):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if not self.ignore_rules.should_ignore_dir(d)]

            for file in filenames:
                full_path = os.path.join(address, file)
                if not self.ignore_rules.should_ignore_file(full_path):
                    files.append(full_path)
        return files


class SecretChecker:
    """Orchestrates multiple analyzers to check a single file."""

    def __init__(self, analyzers: List):
        """
        Args:
            analyzers: List of analyzer objects with an analyze(filepath, lines) method.
        """
        self.analyzers = analyzers

    def check_file(self, filepath: str) -> List[Secret]:
        """
        Run all analyzers on a file and return combined results.
        Args:
            filepath: Path to the file.
        Returns:
            List of Secret objects found.
        """
        secrets = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
                content = "".join(lines)
        except (UnicodeDecodeError, PermissionError, IsADirectoryError):
            return []

        for analyzer in self.analyzers:
            if hasattr(analyzer, 'analyze') and callable(analyzer.analyze):
                try:
                    # AST analyzers need full content, others need lines
                    if isinstance(analyzer, (ASTAnalyzer, JavaASTAnalyzer)):
                        result = analyzer.analyze(filepath, content)
                    else:
                        result = analyzer.analyze(filepath, lines)
                    secrets.extend(result)
                except Exception as e:
                    print(f"{Fore.RED}Error in analyzer {type(analyzer).__name__} for {filepath}: {e}{Style.RESET_ALL}")
        return secrets


class OutputFormatter:
    """Handles console output and JSON saving of results."""

    @staticmethod
    def print_results(secrets: List[Secret]) -> None:
        """Print secrets to console in a formatted table."""
        if not secrets:
            return

        print('┌' + '─' * 58 + '┐')
        print(f'│{Fore.CYAN}{"RESULTS":^58}{Style.RESET_ALL}│')
        print('└' + '─' * 58 + '┘')
        print()

        for idx, s in enumerate(secrets, 1):
            criticality = s.criticality.lower()
            if criticality in ('critical', 'high'):
                color = Fore.RED
            elif criticality == 'medium':
                color = Fore.YELLOW
            elif criticality == 'warning':
                color = Fore.WHITE
            else:
                color = Fore.WHITE

            plain_display = s.plain_string if len(s.plain_string) <= 50 else s.plain_string[:50] + "…"

            print('┌' + '─' * 58 + '┐')
            print(f'│ {Fore.CYAN}Secret #{idx}{Style.RESET_ALL}'.ljust(58) + '│')
            print('├' + '─' * 58 + '┤')
            print(f'│ Found      : {s.secret_type}'.ljust(58) + '│')
            print(f'│ Criticality : {color}{s.criticality}{Style.RESET_ALL}'.ljust(58) + '│')
            print(f'│ File        : {s.filename}'.ljust(58) + '│')
            print(f'│ Line        : {s.line_number}'.ljust(58) + '│')
            print(f'│ Analyzer    : {s.analyzer}'.ljust(58) + '│')
            print('├' + '─' * 58 + '┤')
            print(f'│ Secret: {plain_display}'.ljust(58) + '│')
            print(f'│ {Fore.YELLOW}←{Style.RESET_ALL}'.ljust(58) + '│')
            print(f'│ Recommendation: {s.recommendation}'.ljust(58) + '│')
            print('└' + '─' * 58 + '┘')
            print()

    @staticmethod
    def save_to_json(secrets: List[Secret], filename: str) -> None:
        """Save secrets to JSON file."""
        data = [s.to_dict() for s in secrets]
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"{Fore.GREEN}Results saved to {filename}{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}Error saving results: {e}{Style.RESET_ALL}")


class Scanner:
    """Main scanner class orchestrating the entire process."""

    def __init__(self, config: Config):
        self.config = config
        self.ignore_rules = IgnoreRules(config.ignore_file)
        self.rules = RegexRules(config.rules_file)
        self.file_scanner = FileScanner(config.project_dir, self.ignore_rules)
        analyzers = []
        analyzers.append(RegexCheckerAdapter(self.rules))
        if config.use_entropy:
            analyzers.append(EntropyAnalyzer())
        if config.use_ast:
            ast_keywords = config.get_ast_keywords()
            analyzers.append(ASTAnalyzer(ast_keywords))
            analyzers.append(JavaASTAnalyzer(ast_keywords))

        self.secret_checker = SecretChecker(analyzers)
        self.output = OutputFormatter()
        self.enhancer = CriticalityEnhancer()
        self.all_secrets: List[Secret] = []

    def deduplicate_secrets(self, secrets: List[Secret]) -> List[Secret]:
        """
        Remove duplicate secrets based on file and line number,
        keeping the one with highest priority analyzer.
        """
        unique = {}
        priority = {"regex": 1, "ast": 2, "entropy": 3, "java_ast": 2}  # 1 = highest
        for s in secrets:
            key = (s.filename, s.line_number)
            if key in unique:
                existing = unique[key]
                if priority.get(s.analyzer, 99) < priority.get(existing.analyzer, 99):
                    unique[key] = s
            else:
                unique[key] = s
        return list(unique.values())

    def scan(self) -> None:
        """Run the scan process."""
        print(f"{Fore.CYAN}Scanning directory: {self.config.project_dir}{Style.RESET_ALL}")
        files = self.file_scanner.get_files()
        print(f"Found {len(files)} files to scan.")

        cache = None if self.config.no_cache else ScanCache()
        all_secrets = []

        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            future_to_file = {}
            for f in files:
                if cache:
                    cached = cache.get(f)
                    if cached is not None:
                        all_secrets.extend(cached)
                        continue
                future = executor.submit(self.secret_checker.check_file, f)
                future_to_file[future] = f

            for future in as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    secrets = future.result()
                    if secrets:
                        all_secrets.extend(secrets)
                    if cache:
                        cache.put(file, secrets)
                except Exception as e:
                    print(f"{Fore.RED}Error scanning {file}: {e}{Style.RESET_ALL}")

        self.all_secrets = all_secrets

        if self.all_secrets:
            # Apply criticality enhancement based on directory
            self.all_secrets = self.enhancer.enhance(self.all_secrets)
            self.all_secrets = self.deduplicate_secrets(self.all_secrets)
            self.output.print_results(self.all_secrets)
            self.output.save_to_json(self.all_secrets, self.config.result_filename)
            if self.config.need_html:
                HTMLReportGenerator.generate(self.all_secrets,
                                             self.config.result_filename.replace('.json', '.html'))
        else:
            print(f"{Fore.GREEN}No secrets found.{Style.RESET_ALL}")


class RegexCheckerAdapter:
    """Adapter to use RegexRules as an analyzer."""

    def __init__(self, rules: RegexRules):
        self.rules = rules

    def analyze(self, filepath: str, lines: List[str]) -> List[Secret]:
        """Apply regex rules to each line of the file."""
        secrets = []
        for line_num, line in enumerate(lines, start=1):
            result = self.rules.check_string(line)
            if result:
                rule_name, match, rule = result
                secret = Secret(
                    secret_type=rule_name,
                    filename=filepath,
                    line_number=line_num,
                    plain_string=line.rstrip('\n'),
                    matched_part=match.group(),
                    start=match.start(),
                    end=match.end(),
                    criticality=rule.get("risk group", "unknown"),
                    recommendation=rule.get("recommendation", ""),
                    analyzer="regex"
                )
                secrets.append(secret)
        return secrets


if __name__ == "__main__":
    try:
        cfg = Config()
        scanner = Scanner(cfg)
        scanner.scan()
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        exit(1)
