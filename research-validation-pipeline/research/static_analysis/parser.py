from pathlib import Path
import ast
import json
import logging
from typing import List, Dict, Optional

class FileAST:
    def __init__(self, path: str, imports: List[str], from_imports: Dict[str, List[str]], 
                 aliases: Dict[str, str], function_defs: List[str], function_calls: List[str]):
        self.path = path
        self.imports = imports
        self.from_imports = from_imports
        self.aliases = aliases
        self.function_defs = function_defs
        self.function_calls = function_calls

def parse_file(path: Path) -> Optional[FileAST]:
    try:
        with path.open(encoding="utf-8") as f:
            source = f.read()
    except (SyntaxError, UnicodeDecodeError):
        logging.warning(f"Skipping file due to syntax or encoding error: {path}")
        return None

    tree = ast.parse(source)
    imports = []
    from_imports = {}
    aliases = {}
    function_defs = []
    function_calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            from_imports.setdefault(node.module, []).extend(alias.name for alias in node.names)
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = f"{node.module}.{alias.name}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_defs.append(node.name)
        elif isinstance(node, ast.Call):
            function_calls.append(_resolve_call_name(node.func))

    return FileAST(
        path=str(path.absolute()),
        imports=imports,
        from_imports=from_imports,
        aliases=aliases,
        function_defs=function_defs,
        function_calls=function_calls
    )

def _resolve_call_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return _resolve_call_name(node.value) + "." + node.attr
    return "<unknown>"

def parse_repository(repo_path: str) -> List[FileAST]:
    file_asts = []
    for path in Path(repo_path).rglob("*.py"):
        if any(excluded in path.parts for excluded in ['.git', '__pycache__', 'venv', '.venv', 'node_modules', 'site-packages']):
            continue
        file_ast = parse_file(path)
        if file_ast:
            file_asts.append(file_ast)
    logging.info(f"Parsed {len(file_asts)} Python files.")
    return file_asts