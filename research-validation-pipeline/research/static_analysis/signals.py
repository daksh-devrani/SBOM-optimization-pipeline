from research.models import Vulnerability, StaticSignals
from research.static_analysis.parser import FileAST
from research.utils.logger import get_logger

logger = get_logger(__name__)

def detect_package_usage(vulnerability: Vulnerability, file_asts: list[FileAST]) -> tuple[bool, list[str]]:
    package_root = vulnerability.package.split('==')[0]  # Extract package name without version
    found_paths = []
    
    for file_ast in file_asts:
        if package_root in file_ast.imports or package_root in file_ast.from_imports:
            found_paths.append(file_ast.path)
    
    package_used = len(found_paths) > 0
    logger.info("Package usage detected", extra={"package_used": package_used, "import_locations": found_paths})
    return package_used, found_paths

def detect_function_usage(vulnerability: Vulnerability, file_asts: list[FileAST]) -> tuple[bool, list[str]]:
    found_paths = []
    
    for file_ast in file_asts:
        for affected_function in vulnerability.affected_functions:
            if any(affected_function in call for call in file_ast.function_calls):
                found_paths.append(file_ast.path)
    
    function_used = len(found_paths) > 0
    logger.info("Function usage detected", extra={"function_used": function_used, "function_locations": found_paths})
    return function_used, found_paths

def build_basic_call_graph(file_asts: list[FileAST]) -> dict[str, list[str]]:
    call_graph = {}
    
    for file_ast in file_asts:
        for func_def in file_ast.function_defs:
            call_graph[func_def] = file_ast.call_graph_local.get(func_def, [])
    
    return call_graph

def detect_call_path(target_functions: list[str], call_graph: dict[str, list[str]]) -> bool:
    from collections import deque
    
    visited = set()
    queue = deque(call_graph.keys())
    
    while queue:
        current = queue.popleft()
        if current in target_functions:
            return True
        visited.add(current)
        for neighbor in call_graph.get(current, []):
            if neighbor not in visited:
                queue.append(neighbor)
    
    return False

def detect_input_sources(file_asts: list[FileAST]) -> bool:
    input_patterns = ["input", "sys.argv", "request.form", "request.args", "request.json", "request.data", "flask.request", "fastapi.Request", "os.environ"]
    
    for file_ast in file_asts:
        if any(pattern in call for call in file_ast.function_calls for pattern in input_patterns):
            logger.info("User-controlled input sources detected")
            return True
    
    logger.info("No user-controlled input sources detected")
    return False

def detect_sanitization(file_asts: list[FileAST]) -> bool:
    sanitization_patterns = ["html.escape", "bleach.clean", "re.sub", "re.escape", "sanitize", "validate", "escape", "quote", "urllib.parse.quote"]
    
    for file_ast in file_asts:
        if any(pattern in call for call in file_ast.function_calls for pattern in sanitization_patterns):
            logger.info("Sanitization detected")
            return True
    
    logger.info("No sanitization detected")
    return False

def compute_static_signals(vulnerability: Vulnerability, file_asts: list[FileAST], call_graph: dict[str, list[str]]) -> StaticSignals:
    package_used, import_locations = detect_package_usage(vulnerability, file_asts)
    function_used, function_locations = detect_function_usage(vulnerability, file_asts)
    call_path_exists = detect_call_path(vulnerability.affected_functions, call_graph)
    input_controlled = detect_input_sources(file_asts)
    sanitized = detect_sanitization(file_asts)
    
    signals = StaticSignals(
        package_used=package_used,
        function_used=function_used,
        call_path_exists=call_path_exists,
        import_locations=import_locations,
        function_locations=function_locations,
        input_controlled=input_controlled,
        sanitized=sanitized
    )
    
    logger.info("Computed static signals", extra={"signals": signals})
    return signals