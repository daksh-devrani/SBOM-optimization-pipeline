"""
AST-based repository parser for Python source files.

Walks a repository directory tree, parses every .py file using Python's
stdlib `ast` module, and extracts a structured inventory per file:
  - imports and from-imports
  - import aliases (e.g. `import numpy as np`)
  - function definitions
  - function calls (with alias resolution)
  - per-function call graph (which functions each function calls)

Only Python files are supported. Files with syntax errors or encoding
issues are skipped gracefully with a logged warning.
"""

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Directories to skip during repository walk
_EXCLUDED_DIRS = frozenset({
    ".git", "__pycache__", "venv", ".venv", "node_modules",
    "site-packages", ".tox", "dist", "build", ".eggs",
})


@dataclass
class FileAST:
    """Structured AST inventory extracted from a single Python source file."""

    path: str
    """Absolute path to the source file."""

    imports: list[str] = field(default_factory=list)
    """Top-level module names from `import X` statements. e.g. ['requests', 'os']"""

    from_imports: dict[str, list[str]] = field(default_factory=dict)
    """Module → list of names from `from X import Y`. e.g. {'os': ['path', 'getcwd']}"""

    aliases: dict[str, str] = field(default_factory=dict)
    """alias → real name. e.g. {'np': 'numpy', 'pd': 'pandas'}"""

    function_defs: list[str] = field(default_factory=list)
    """Names of all function definitions in the file (including nested)."""

    function_calls: list[str] = field(default_factory=list)
    """All call expressions in the file with alias resolution applied."""

    call_graph_local: dict[str, list[str]] = field(default_factory=dict)
    """function_name → list of call names made inside that function body."""


def _resolve_call_name(node: ast.expr) -> str:
    """
    Recursively reconstruct a dotted call name from an AST call node.

    Handles:
      - ast.Name: simple name e.g. `open`
      - ast.Attribute: dotted access e.g. `requests.get`
      - Everything else: returns '<unknown>'
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_call_name(node.value)
        return f"{parent}.{node.attr}"
    return "<unknown>"


def _resolve_alias(name: str, aliases: dict[str, str]) -> str:
    """
    Replace the first segment of a dotted name if it is an alias.

    Example:
        name='np.array', aliases={'np': 'numpy'} → 'numpy.array'
        name='requests', aliases={} → 'requests'
    """
    parts = name.split(".", 1)
    real = aliases.get(parts[0])
    if real is None:
        return name
    if len(parts) == 1:
        return real
    return f"{real}.{parts[1]}"


def parse_file(path: Path) -> Optional[FileAST]:
    """
    Parse a single Python file and return its AST inventory.

    Tries UTF-8 encoding first, falls back to latin-1 for legacy files.
    Returns None if the file cannot be parsed (syntax error or unreadable).
    """
    source: Optional[str] = None
    for encoding in ("utf-8", "latin-1"):
        try:
            source = path.read_text(encoding=encoding)
            break
        except UnicodeDecodeError:
            continue
        except OSError as e:
            logger.warning("Cannot read file %s: %s", path, e)
            return None

    if source is None:
        logger.warning("Could not decode file (tried utf-8 and latin-1): %s", path)
        return None

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        logger.warning("Syntax error in %s (line %s): %s", path, e.lineno, e.msg)
        return None

    imports: list[str] = []
    from_imports: dict[str, list[str]] = {}
    aliases: dict[str, str] = {}
    function_defs: list[str] = []
    raw_calls: list[str] = []
    call_graph_local: dict[str, list[str]] = {}

    # ── First pass: collect imports and aliases ───────────────────────────────
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
                if alias.asname:
                    aliases[alias.asname] = alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [a.name for a in node.names]
            from_imports.setdefault(module, []).extend(names)
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = f"{module}.{alias.name}"

    # ── Second pass: collect function defs, all calls, and local call graph ───
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_defs.append(node.name)

            # Build the per-function call list by walking the function body.
            # Note: ast.walk includes nested function bodies too, which is
            # acceptable for this basic call graph — no interprocedural analysis.
            func_calls: list[str] = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _resolve_call_name(child.func)
                    if name != "<unknown>":
                        func_calls.append(name)
            call_graph_local[node.name] = func_calls

        elif isinstance(node, ast.Call):
            name = _resolve_call_name(node.func)
            raw_calls.append(name)

    # ── Resolve aliases in all collected call names ───────────────────────────
    function_calls = [_resolve_alias(c, aliases) for c in raw_calls]

    return FileAST(
        path=str(path.resolve()),
        imports=imports,
        from_imports=from_imports,
        aliases=aliases,
        function_defs=function_defs,
        function_calls=function_calls,
        call_graph_local=call_graph_local,
    )


def parse_repository(repo_path: str) -> list[FileAST]:
    """
    Walk a repository directory and parse all Python source files.

    Args:
        repo_path: Filesystem path to the root of the repository.

    Returns:
        List of FileAST objects, one per successfully parsed .py file.
        Files in excluded directories are silently skipped.
    """
    results: list[FileAST] = []
    root = Path(repo_path)

    if not root.exists():
        logger.warning("Repository path does not exist: %s", repo_path)
        return results

    for py_file in root.rglob("*.py"):
        # Skip excluded directories (check every component of the path)
        if any(part in _EXCLUDED_DIRS for part in py_file.parts):
            continue

        file_ast = parse_file(py_file)
        if file_ast is not None:
            results.append(file_ast)

    logger.info("Parsed %d Python files from %s", len(results), repo_path)
    return results
