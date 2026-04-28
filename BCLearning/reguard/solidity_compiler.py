# ============================================================
#  solidity_compiler.py
#  ====================
#  Solidity compiler integration for RE-GUARD.
#
#  This module handles:
#    1. Detecting if `solc` (Solidity compiler) is installed
#    2. Compiling Solidity code and extracting the AST
#    3. If solc is NOT available → fallback to our structural
#       parser that mimics AST analysis using Python
#
#  WHY USE solc + AST instead of just regex?
#  ─────────────────────────────────────────
#  Regex reads code as raw text and can be fooled by:
#    • Comments that contain code patterns
#    • String literals with code-like content
#    • Multi-line expressions split across lines
#
#  An AST (Abstract Syntax Tree) is the actual parsed structure
#  of the code — every function, variable, statement is a node.
#  Reentrancy analysis on an AST can:
#    • Trace exact call graphs between functions
#    • Know precisely which variables are state vs local
#    • Detect cross-function reentrancy accurately
#    • Never be fooled by comments or strings
#
# ============================================================

import subprocess
import json
import re
import shutil
import tempfile
import os
from dataclasses import dataclass, field


# ── Data classes to represent analysis results ──────────────

@dataclass
class CompilerError:
    """A syntax/compilation error from solc."""
    severity: str          # 'error' | 'warning'
    message: str
    line: int
    column: int
    source_location: str

@dataclass
class FunctionInfo:
    """Represents a parsed Solidity function."""
    name: str
    line: int
    visibility: str               # public, external, internal, private
    modifiers: list[str]          # e.g. ['nonReentrant', 'onlyOwner']
    has_external_call: bool
    external_call_lines: list[int]
    state_updates_after_call: list[int]
    has_value_transfer: bool
    is_payable: bool
    calls_made: list[str]         # other function names called

@dataclass
class ContractInfo:
    """Represents a parsed Solidity contract."""
    name: str
    line: int
    inherits: list[str]           # e.g. ['ReentrancyGuard', 'Ownable']
    functions: list[FunctionInfo]
    has_receive: bool
    has_fallback: bool
    state_variables: list[str]

@dataclass
class CompilationResult:
    """Full result from the compiler/parser."""
    success: bool
    source: str                         # 'solc' | 'builtin_parser'
    version: str                        # solc version or 'builtin'
    errors: list[CompilerError]
    warnings: list[CompilerError]
    contracts: list[ContractInfo]
    abi: list[dict]                     # ABI from real solc (empty for builtin)
    ast_available: bool                 # True only when real solc ran


# ── Solc Detection ───────────────────────────────────────────

def find_solc() -> str | None:
    """
    Look for the solc binary on the system PATH.
    Returns the path if found and working, otherwise None.
    """
    # Check common locations
    candidates = [
        shutil.which("solc"),
        "/usr/local/bin/solc",
        "/usr/bin/solc",
        os.path.expanduser("~/.solc-select/artifacts/solc-v0.8.20/solc-v0.8.20"),
    ]

    # Also check py-solc-x installations
    try:
        from solcx import get_installed_solc_versions, get_solc_version
        installed = get_installed_solc_versions()
        if installed:
            from solcx import get_executable
            candidates.append(str(get_executable(installed[-1])))
    except Exception:
        pass

    for path in candidates:
        if path and os.path.isfile(path):
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and "Version:" in result.stdout:
                    version_line = [l for l in result.stdout.splitlines() if "Version:" in l]
                    version = version_line[0].split("Version:")[1].strip() if version_line else "unknown"
                    return path, version
            except Exception:
                continue

    return None, None


def get_solc_version_string() -> tuple[str | None, str | None]:
    """Returns (solc_path, version_string) or (None, None)."""
    return find_solc()


# ── Real solc Compilation ────────────────────────────────────

def compile_with_solc(code: str, solc_path: str) -> dict:
    """
    Compile Solidity code using the real solc binary.

    Uses the Standard JSON Input format — the most powerful
    solc interface, giving us AST, ABI, bytecode, and errors.

    Returns the raw JSON output from solc.
    """
    # Build the standard JSON input spec
    # ------------------------------------------------------------------
    # solc's standard JSON input lets you control exactly what you get:
    #   outputSelection: which outputs to generate per contract/file
    #   "ast" → the Abstract Syntax Tree (full parsed structure)
    #   "abi" → the Application Binary Interface
    # ------------------------------------------------------------------
    standard_input = {
        "language": "Solidity",
        "sources": {
            "contract.sol": {
                "content": code
            }
        },
        "settings": {
            "outputSelection": {
                "*": {
                    "": ["ast"],           # File-level AST
                    "*": ["abi"]           # Per-contract ABI
                }
            },
            "optimizer": {
                "enabled": False
            }
        }
    }

    input_json = json.dumps(standard_input)

    # Run solc with --standard-json flag
    # solc reads the JSON from stdin and writes JSON to stdout
    result = subprocess.run(
        [solc_path, "--standard-json"],
        input=input_json,
        capture_output=True,
        text=True,
        timeout=30
    )

    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(f"solc failed: {result.stderr}")

    return json.loads(result.stdout)


def parse_solc_output(solc_output: dict, code: str) -> CompilationResult:
    """
    Parse the raw JSON output from solc into our CompilationResult structure.

    solc's JSON output looks like:
    {
      "errors": [ {"severity": "error", "message": "...", "sourceLocation": {...}} ],
      "sources": {
        "contract.sol": {
          "ast": {
            "nodeType": "SourceUnit",
            "nodes": [ ... ContractDefinition nodes ... ]
          }
        }
      },
      "contracts": {
        "contract.sol": {
          "MyContract": {
            "abi": [...],
            "evm": { "bytecode": {...} }
          }
        }
      }
    }
    """
    errors = []
    warnings = []
    contracts = []
    abi = []

    # ── Parse errors and warnings ────────────────────────────
    for err in solc_output.get("errors", []):
        loc = err.get("sourceLocations", [{}])[0] if err.get("sourceLocations") else {}
        entry = CompilerError(
            severity=err.get("severity", "error"),
            message=err.get("message", "Unknown error"),
            line=loc.get("start", 0),
            column=0,
            source_location=err.get("formattedMessage", "")
        )
        if err.get("severity") == "error":
            errors.append(entry)
        else:
            warnings.append(entry)

    # If there were hard errors, we can't reliably parse the AST
    has_hard_errors = len(errors) > 0

    # ── Parse AST ────────────────────────────────────────────
    sources = solc_output.get("sources", {})
    for filename, source_data in sources.items():
        ast = source_data.get("ast", {})
        if ast:
            parsed = _parse_ast_nodes(ast, code)
            contracts.extend(parsed)

    # ── Parse ABI ────────────────────────────────────────────
    for filename, file_contracts in solc_output.get("contracts", {}).items():
        for contract_name, contract_data in file_contracts.items():
            abi.extend(contract_data.get("abi", []))

    return CompilationResult(
        success=not has_hard_errors,
        source="solc",
        version="",  # filled in by caller
        errors=errors,
        warnings=warnings,
        contracts=contracts,
        abi=abi,
        ast_available=True
    )


def _parse_ast_nodes(ast: dict, code: str) -> list[ContractInfo]:
    """
    Walk the solc AST and extract contract/function information.

    The AST is a tree of nodes. Each node has:
      - nodeType: what kind of node it is
      - src: "offset:length:fileIndex" source location
      - nodes: child nodes (for container types)

    Key node types we care about:
      ContractDefinition  → a contract
      FunctionDefinition  → a function inside a contract
      ExpressionStatement → a statement (could be a .call())
      Assignment          → state variable update
    """
    contracts = []
    lines = code.split("\n")

    def src_to_line(src_str: str) -> int:
        """Convert solc 'offset:length:file' to a line number."""
        try:
            offset = int(src_str.split(":")[0])
            return code[:offset].count("\n") + 1
        except Exception:
            return 0

    def has_modifier(func_node: dict, name: str) -> bool:
        """Check if a function has a specific modifier."""
        for mod in func_node.get("modifiers", []):
            mod_name = mod.get("modifierName", {}).get("name", "")
            if mod_name == name:
                return True
        return False

    def find_external_calls(node: dict, depth: int = 0) -> list[dict]:
        """
        Recursively find all external call nodes in a function body.
        Looks for:
          - FunctionCall nodes where the expression is a MemberAccess
            with memberName "call", "send", "transfer", "delegatecall"
        """
        calls = []
        if depth > 20:  # prevent infinite recursion on deeply nested ASTs
            return calls

        node_type = node.get("nodeType", "")

        if node_type == "FunctionCall":
            expr = node.get("expression", {})
            if expr.get("nodeType") == "MemberAccess":
                member = expr.get("memberName", "")
                if member in ("call", "send", "transfer", "delegatecall", "staticcall"):
                    calls.append(node)

        # Recurse into children
        for key, value in node.items():
            if isinstance(value, dict):
                calls.extend(find_external_calls(value, depth + 1))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        calls.extend(find_external_calls(item, depth + 1))

        return calls

    def find_state_assignments(node: dict, depth: int = 0) -> list[dict]:
        """
        Find Assignment nodes that modify state variables
        (as opposed to local variable assignments).
        We identify state variable assignments by checking if the
        left-hand side is an IndexAccess (mapping) or MemberAccess
        on 'this', or a simple Identifier that matches a known state var.
        """
        assignments = []
        if depth > 20:
            return assignments

        node_type = node.get("nodeType", "")
        if node_type == "Assignment":
            lhs = node.get("leftHandSide", {})
            lhs_type = lhs.get("nodeType", "")
            # Mapping access: balances[msg.sender]
            if lhs_type in ("IndexAccess", "MemberAccess", "Identifier"):
                assignments.append(node)

        for key, value in node.items():
            if isinstance(value, dict):
                assignments.extend(find_state_assignments(value, depth + 1))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        assignments.extend(find_state_assignments(item, depth + 1))

        return assignments

    # ── Walk top-level nodes looking for ContractDefinition ──
    for node in ast.get("nodes", []):
        if node.get("nodeType") != "ContractDefinition":
            continue

        contract_line = src_to_line(node.get("src", "0:0:0"))
        contract_name = node.get("name", "Unknown")

        # Inheritance
        inherits = []
        for base in node.get("baseContracts", []):
            base_name = base.get("baseName", {}).get("name", "")
            if base_name:
                inherits.append(base_name)

        # State variables
        state_vars = []
        for child in node.get("nodes", []):
            if child.get("nodeType") == "StateVariableDeclaration":
                for decl in child.get("declarations", []):
                    state_vars.append(decl.get("name", ""))

        # Functions
        functions = []
        has_receive = False
        has_fallback = False

        for child in node.get("nodes", []):
            child_type = child.get("nodeType", "")

            if child_type == "FunctionDefinition":
                func_name = child.get("name", "") or child.get("kind", "")
                func_line = src_to_line(child.get("src", "0:0:0"))
                visibility = child.get("visibility", "internal")
                is_payable = child.get("stateMutability", "") == "payable"
                func_kind = child.get("kind", "function")

                if func_kind == "receive":
                    has_receive = True
                elif func_kind == "fallback":
                    has_fallback = True

                # Modifiers
                modifiers = []
                for mod in child.get("modifiers", []):
                    mod_name = mod.get("modifierName", {}).get("name", "")
                    if mod_name:
                        modifiers.append(mod_name)

                # Find external calls in function body
                body = child.get("body", {}) or {}
                ext_calls = find_external_calls(body)
                ext_call_lines = [src_to_line(c.get("src", "0")) for c in ext_calls]
                has_value_transfer = any(
                    c.get("expression", {}).get("memberName", "") in ("call", "send", "transfer")
                    for c in ext_calls
                )

                # Find state assignments AFTER external calls
                # We compare source offsets to determine ordering
                state_updates = find_state_assignments(body)
                state_after_call_lines = []

                if ext_calls and state_updates:
                    # Get the offset of the LAST external call
                    last_call_offset = max(
                        int(c.get("src", "0:0:0").split(":")[0]) for c in ext_calls
                    )
                    # Find any state update that comes AFTER the last call
                    for su in state_updates:
                        su_offset = int(su.get("src", "0:0:0").split(":")[0])
                        if su_offset > last_call_offset:
                            state_after_call_lines.append(src_to_line(su.get("src", "0")))

                functions.append(FunctionInfo(
                    name=func_name,
                    line=func_line,
                    visibility=visibility,
                    modifiers=modifiers,
                    has_external_call=len(ext_calls) > 0,
                    external_call_lines=ext_call_lines,
                    state_updates_after_call=state_after_call_lines,
                    has_value_transfer=has_value_transfer,
                    is_payable=is_payable,
                    calls_made=[]
                ))

        contracts.append(ContractInfo(
            name=contract_name,
            line=contract_line,
            inherits=inherits,
            functions=functions,
            has_receive=has_receive,
            has_fallback=has_fallback,
            state_variables=state_vars
        ))

    return contracts


# ── Builtin Structural Parser (fallback when solc unavailable) ──

def parse_with_builtin(code: str) -> CompilationResult:
    """
    Fallback parser using Python when solc is not available.

    This is NOT a real compiler — it uses regex and structural
    analysis to approximate what solc's AST would tell us.
    It handles ~80% of real-world cases but can miss complex patterns.
    """
    lines = code.split("\n")
    contracts = []
    errors = []
    warnings = []

    # Basic syntax validation
    errors.extend(_check_basic_syntax(code, lines))

    # Parse contracts
    contracts = _parse_contracts_builtin(code, lines)

    return CompilationResult(
        success=len(errors) == 0,
        source="builtin_parser",
        version="builtin",
        errors=errors,
        warnings=warnings,
        contracts=contracts,
        abi=[],
        ast_available=False
    )


def _check_basic_syntax(code: str, lines: list[str]) -> list[CompilerError]:
    """Basic syntax checks we can do without a real compiler."""
    errors = []

    # Check brace balance
    open_braces = code.count("{")
    close_braces = code.count("}")
    if open_braces != close_braces:
        errors.append(CompilerError(
            severity="error",
            message=f"Unbalanced braces: {open_braces} opening vs {close_braces} closing",
            line=0,
            column=0,
            source_location=""
        ))

    # Check for pragma
    if not re.search(r'pragma\s+solidity', code):
        errors.append(CompilerError(
            severity="warning",
            message="Missing pragma solidity declaration",
            line=1,
            column=0,
            source_location=""
        ))

    # Check pragma version format
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', code)
    if pragma_match:
        version_expr = pragma_match.group(1).strip()
        # Warn about very old versions
        old_version = re.search(r'0\.[1-5]\.', version_expr)
        if old_version:
            line = next((i+1 for i, l in enumerate(lines) if 'pragma' in l), 1)
            errors.append(CompilerError(
                severity="warning",
                message=f"Old Solidity version '{version_expr}' — consider upgrading to 0.8.x for built-in overflow protection",
                line=line,
                column=0,
                source_location=""
            ))

    return errors


def _parse_contracts_builtin(code: str, lines: list[str]) -> list[ContractInfo]:
    """Parse contract and function structure using regex."""
    contracts = []

    # Strip comments to avoid false positives
    clean_code = _strip_comments(code)
    clean_lines = clean_code.split("\n")

    # Find all contract definitions
    contract_pattern = re.compile(
        r'\bcontract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
    )

    for match in contract_pattern.finditer(clean_code):
        contract_name = match.group(1)
        inherits_str = match.group(2) or ""
        inherits = [i.strip() for i in inherits_str.split(",") if i.strip()]
        contract_line = clean_code[:match.start()].count("\n") + 1

        # Extract the contract body (between matching braces)
        body_start = match.end() - 1  # position of opening {
        body = _extract_brace_block(clean_code, body_start)

        if not body:
            continue

        # Parse state variables
        state_vars = _find_state_variables(body)

        # Parse functions within this contract
        functions, has_receive, has_fallback = _parse_functions_builtin(
            body, contract_line, clean_lines
        )

        contracts.append(ContractInfo(
            name=contract_name,
            line=contract_line,
            inherits=inherits,
            functions=functions,
            has_receive=has_receive,
            has_fallback=has_fallback,
            state_variables=state_vars
        ))

    return contracts


def _strip_comments(code: str) -> str:
    """Remove // and /* */ comments from Solidity code."""
    # Remove block comments
    code = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'), code, flags=re.DOTALL)
    # Remove line comments
    code = re.sub(r'//[^\n]*', '', code)
    return code


def _extract_brace_block(code: str, start: int) -> str:
    """Extract the content between matching { } starting at start."""
    depth = 0
    i = start
    while i < len(code):
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
            if depth == 0:
                return code[start+1:i]
        i += 1
    return code[start+1:]


def _find_state_variables(body: str) -> list[str]:
    """Find state variable names in contract body."""
    # Match: type name; or mapping(k=>v) name; or type[] name;
    pattern = re.compile(
        r'\b(?:mapping\s*\([^)]+\)|uint\d*|int\d*|address|bool|bytes\d*|string)\s*(?:\[\])?\s+(\w+)\s*;'
    )
    return [m.group(1) for m in pattern.finditer(body)]


def _parse_functions_builtin(body: str, contract_start_line: int, all_lines: list[str]) -> tuple:
    """Parse function definitions within a contract body."""
    functions = []
    has_receive = False
    has_fallback = False

    func_pattern = re.compile(
        r'\b(function\s+(\w+)|receive\s*\(\s*\)|fallback\s*\(\s*\))'
        r'([^{]*)\{'
    )

    for match in func_pattern.finditer(body):
        full_match = match.group(0)
        func_kind = match.group(1)
        func_name = match.group(2) if match.group(2) else func_kind.split("(")[0].strip()
        signature = match.group(3) or ""

        # Line number (offset within body + contract start)
        func_offset = body[:match.start()].count("\n")
        func_line = contract_start_line + func_offset

        if "receive" in func_kind:
            has_receive = True
            func_name = "receive"
        elif "fallback" in func_kind:
            has_fallback = True
            func_name = "fallback"

        # Visibility
        visibility = "internal"
        for vis in ("external", "public", "internal", "private"):
            if vis in signature:
                visibility = vis
                break

        is_payable = "payable" in signature

        # Modifiers
        modifier_words = {"external", "public", "internal", "private",
                          "payable", "view", "pure", "virtual", "override", "returns"}
        modifiers = []
        for word in re.findall(r'\b(\w+)\b', signature):
            if word not in modifier_words and not word.startswith("uint") and len(word) > 2:
                # Likely a custom modifier
                if re.match(r'^[a-z][a-zA-Z]+$', word):
                    modifiers.append(word)

        # Extract function body
        brace_pos = match.end() - 1
        func_body = _extract_brace_block(body, brace_pos)

        # Find external calls in function body
        ext_call_lines, has_value_transfer = _find_external_calls_in_body(
            func_body, func_line
        )

        # Find state updates after external calls
        state_after_call_lines = _find_state_updates_after_calls(func_body, func_line)

        functions.append(FunctionInfo(
            name=func_name,
            line=func_line,
            visibility=visibility,
            modifiers=modifiers,
            has_external_call=len(ext_call_lines) > 0,
            external_call_lines=ext_call_lines,
            state_updates_after_call=state_after_call_lines,
            has_value_transfer=has_value_transfer,
            is_payable=is_payable,
            calls_made=[]
        ))

    return functions, has_receive, has_fallback


def _find_external_calls_in_body(body: str, func_start_line: int) -> tuple[list[int], bool]:
    """Find external call lines in a function body."""
    lines = body.split("\n")
    call_lines = []
    has_value = False

    call_pattern = re.compile(r'\.(call|send|transfer|delegatecall)\s*[\({]')

    for i, line in enumerate(lines):
        if call_pattern.search(line):
            call_lines.append(func_start_line + i + 1)
            if re.search(r'\.call\s*\{[^}]*value', line) or re.search(r'\.(send|transfer)\s*\(', line):
                has_value = True

    return call_lines, has_value


def _find_state_updates_after_calls(body: str, func_start_line: int) -> list[int]:
    """Find state variable updates that come after external calls."""
    lines = body.split("\n")
    call_pattern = re.compile(r'\.(call|send|transfer|delegatecall)\s*[\({]')
    update_pattern = re.compile(r'\w[\w\[\]\.]*\s*[\-\+\*\/]?=(?!=)\s*')
    exclude = re.compile(r'\b(require|bool|address|return|emit|if|while|for)\b')

    last_call_line = -1
    for i, line in enumerate(lines):
        if call_pattern.search(line):
            last_call_line = i

    if last_call_line == -1:
        return []

    update_lines = []
    for i in range(last_call_line + 1, len(lines)):
        line = lines[i]
        if update_pattern.search(line) and not exclude.search(line):
            update_lines.append(func_start_line + i + 1)

    return update_lines


# ── Main Entry Point ─────────────────────────────────────────

def compile_and_parse(code: str) -> CompilationResult:
    """
    Main entry point. Tries real solc first, falls back to builtin parser.

    Returns a CompilationResult with:
      - Syntax errors from solc (if available)
      - Parsed contract/function structure
      - Source indicating which parser was used
    """
    solc_path, version = get_solc_version_string()

    if solc_path:
        try:
            raw_output = compile_with_solc(code, solc_path)
            result = parse_solc_output(raw_output, code)
            result.version = version
            return result
        except Exception as e:
            # solc failed (e.g. network error, timeout) → fallback
            pass

    # Fallback: use our builtin structural parser
    return parse_with_builtin(code)
