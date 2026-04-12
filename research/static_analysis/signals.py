"""
Static signal extraction for vulnerability analysis.

Given a Vulnerability and the list of FileAST objects produced by the parser,
this module computes a StaticSignals object that describes how (and whether)
the vulnerable package and its affected functions are used in the codebase.
"""

import logging
from collections import defaultdict, deque
from typing import Optional

from research.models import StaticSignals, Vulnerability
from research.static_analysis.parser import FileAST
from research.utils.logger import get_logger

logger = get_logger(__name__)


def detect_package_usage(
    vulnerability: Vulnerability,
    file_asts: list[FileAST],
) -> tuple[bool, list[str]]:
    """
    Determine whether the vulnerable package is imported anywhere in the repo.

    Checks both `import X` and `from X import Y` forms.
    Also checks aliases — if `numpy` is aliased as `np`, a search for `numpy`
    will still find it.

    Args:
        vulnerability: The vulnerability whose package to search for.
        file_asts:     Parsed AST inventory of the repository.

    Returns:
        Tuple of (package_used: bool, import_locations: list[str]).
    """
    # Strip version specifiers if present (e.g. "requests>=2.0" → "requests")
    package_root = vulnerability.package.split(">=")[0].split("==")[0].split("<=")[0].strip()
    # Normalize: PyPI often uses hyphens in names but imports use underscores
    package_variants = {package_root, package_root.replace("-", "_"), package_root.replace("_", "-")}

    found_paths: list[str] = []

    for file_ast in file_asts:
        matched = False

        # Check `import X` statements
        for imp in file_ast.imports:
            root = imp.split(".")[0]
            if root in package_variants:
                matched = True
                break

        # Check `from X import Y` statements
        if not matched:
            for module_name in file_ast.from_imports:
                root = module_name.split(".")[0]
                if root in package_variants:
                    matched = True
                    break

        # Check if any alias maps back to the package
        if not matched:
            for real_name in file_ast.aliases.values():
                root = real_name.split(".")[0]
                if root in package_variants:
                    matched = True
                    break

        if matched:
            found_paths.append(file_ast.path)

    package_used = len(found_paths) > 0
    logger.info(
        "Package usage detection complete",
        extra={"package": package_root, "package_used": package_used, "locations": found_paths},
    )
    return package_used, found_paths


def detect_function_usage(
    vulnerability: Vulnerability,
    file_asts: list[FileAST],
) -> tuple[bool, list[str]]:
    """
    Determine whether any of the vulnerability's affected functions are called.

    Performs both exact match and suffix match:
      e.g. affected_function="requests.get" matches call "requests.get" (exact)
           and call "get" if that is a short-form call (suffix).

    Args:
        vulnerability: The vulnerability with affected_functions list.
        file_asts:     Parsed AST inventory of the repository.

    Returns:
        Tuple of (function_used: bool, function_locations: list[str]).
    """
    if not vulnerability.affected_functions:
        logger.info("No affected functions specified for %s — skipping function usage check", vulnerability.id)
        return False, []

    found_paths: list[str] = []

    for file_ast in file_asts:
        matched = False
        for call in file_ast.function_calls:
            for affected in vulnerability.affected_functions:
                # Exact match
                if call == affected:
                    matched = True
                    break
                # Suffix match: "get" matches "requests.get"
                if affected.endswith(f".{call}") or call.endswith(f".{affected.split('.')[-1]}"):
                    matched = True
                    break
            if matched:
                break

        if matched:
            found_paths.append(file_ast.path)

    function_used = len(found_paths) > 0
    logger.info(
        "Function usage detection complete",
        extra={
            "vulnerability_id": vulnerability.id,
            "affected_functions": vulnerability.affected_functions,
            "function_used": function_used,
            "locations": found_paths,
        },
    )
    return function_used, found_paths


def build_basic_call_graph(file_asts: list[FileAST]) -> dict[str, list[str]]:
    """
    Merge per-file call graphs into a single repository-level call graph.

    The graph maps: function_name → list of function/call names it invokes.

    If the same function name appears in multiple files (common in large repos),
    the call lists are merged. This is a basic approximation — no module-level
    disambiguation is performed.

    Args:
        file_asts: Parsed AST inventory of the repository.

    Returns:
        Dict mapping function name to list of calls made within it.
    """
    merged: dict[str, list[str]] = defaultdict(list)

    for file_ast in file_asts:
        for func_name, calls in file_ast.call_graph_local.items():
            merged[func_name].extend(calls)

    return dict(merged)


def detect_call_path(
    target_functions: list[str],
    call_graph: dict[str, list[str]],
) -> bool:
    """
    BFS search through the call graph to find if any function eventually
    calls one of the target (vulnerable) functions.

    Args:
        target_functions: List of vulnerable function names to search for.
        call_graph:       Repository-level call graph from build_basic_call_graph.

    Returns:
        True if any path from any function leads to a target function.
    """
    if not target_functions or not call_graph:
        return False

    target_set = set(target_functions)

    # Also check short names (last segment of dotted names)
    target_short = {t.split(".")[-1] for t in target_functions}

    visited: set[str] = set()
    queue: deque[str] = deque(call_graph.keys())

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        for callee in call_graph.get(current, []):
            if callee in target_set or callee in target_short:
                return True
            if callee not in visited:
                queue.append(callee)

    return False


def detect_input_sources(file_asts: list[FileAST]) -> bool:
    """
    Heuristic check: does any file receive user-controlled input?

    Looks for known input-source call patterns in function_calls.

    Args:
        file_asts: Parsed AST inventory of the repository.

    Returns:
        True if any user-controlled input source is detected.
    """
    input_patterns = {
        "input",
        "sys.argv",
        "request.form",
        "request.args",
        "request.json",
        "request.data",
        "request.get_data",
        "flask.request",
        "fastapi.Request",
        "os.environ",
        "os.getenv",
        "argparse.ArgumentParser",
    }

    for file_ast in file_asts:
        for call in file_ast.function_calls:
            # Check exact match or suffix match
            if call in input_patterns:
                logger.info("Input source detected: %s in %s", call, file_ast.path)
                return True
            for pattern in input_patterns:
                if call.endswith(f".{pattern.split('.')[-1]}") and pattern in call:
                    logger.info("Input source detected: %s in %s", call, file_ast.path)
                    return True

    logger.info("No user-controlled input sources detected")
    return False


def detect_sanitization(file_asts: list[FileAST]) -> bool:
    """
    Heuristic check: does any file apply sanitization before sensitive calls?

    Looks for known sanitization call patterns in function_calls.

    Args:
        file_asts: Parsed AST inventory of the repository.

    Returns:
        True if any sanitization call is detected.
    """
    sanitization_patterns = {
        "html.escape",
        "bleach.clean",
        "re.sub",
        "re.escape",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "cgi.escape",
        "markupsafe.escape",
    }
    # Partial name patterns (match as substring)
    partial_patterns = {"sanitize", "validate", "escape", "quote", "clean"}

    for file_ast in file_asts:
        for call in file_ast.function_calls:
            if call in sanitization_patterns:
                logger.info("Sanitization detected: %s in %s", call, file_ast.path)
                return True
            call_lower = call.lower()
            for partial in partial_patterns:
                if partial in call_lower:
                    logger.info("Sanitization pattern detected: %s in %s", call, file_ast.path)
                    return True

    logger.info("No sanitization detected")
    return False


def compute_static_signals(
    vulnerability: Vulnerability,
    file_asts: list[FileAST],
    call_graph: dict[str, list[str]],
    input_controlled_override: Optional[bool] = None,
    sanitized_override: Optional[bool] = None,
) -> StaticSignals:
    """
    Compute the full StaticSignals for a given vulnerability.

    Args:
        vulnerability:             The vulnerability to analyze.
        file_asts:                 Pre-parsed repository AST inventory.
        call_graph:                Pre-built repository call graph.
        input_controlled_override: If set, skip detection and use this value.
        sanitized_override:        If set, skip detection and use this value.

    Returns:
        Populated StaticSignals object.
    """
    package_used, import_locations = detect_package_usage(vulnerability, file_asts)
    function_used, function_locations = detect_function_usage(vulnerability, file_asts)
    call_path_exists = detect_call_path(vulnerability.affected_functions, call_graph)

    if input_controlled_override is not None:
        input_controlled = input_controlled_override
    else:
        input_controlled = detect_input_sources(file_asts)

    if sanitized_override is not None:
        sanitized = sanitized_override
    else:
        sanitized = detect_sanitization(file_asts)

    signals = StaticSignals(
        package_used=package_used,
        function_used=function_used,
        call_path_exists=call_path_exists,
        import_locations=import_locations,
        function_locations=function_locations,
        input_controlled=input_controlled,
        sanitized=sanitized,
    )

    logger.info(
        "Static signals computed",
        extra={
            "vulnerability_id": vulnerability.id,
            "package_used": package_used,
            "function_used": function_used,
            "call_path_exists": call_path_exists,
            "input_controlled": input_controlled,
            "sanitized": sanitized,
        },
    )
    return signals
