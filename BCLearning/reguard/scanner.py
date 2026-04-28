# ============================================================
#  scanner.py  —  Reentrancy vulnerability detector
#  =================================================
#  Now with TWO analysis modes:
#
#  Mode 1 — AST Analysis (when solc is available)
#    Uses the parsed contract/function structure from
#    solidity_compiler.py to do accurate analysis.
#    Knows exactly which variables are state vs local.
#    Can trace cross-function call relationships.
#
#  Mode 2 — Regex Analysis (fallback)
#    The original line-by-line text scanner.
#    Fast, works without solc, catches ~80% of cases.
#
#  Both modes produce the same finding dict format.
# ============================================================

import re
from solidity_compiler import (
    compile_and_parse, CompilationResult,
    ContractInfo, FunctionInfo
)


# ── Vulnerability Pattern Definitions ───────────────────────

VULNERABILITY_PATTERNS = [
    {
        "id": "reentrancy_guard_present",
        "name": "ReentrancyGuard Present",
        "severity": "info",
        "desc": "OpenZeppelin ReentrancyGuard is imported or nonReentrant modifier is used. This is good protective measure.",
        "fix": None,
    },
    {
        "id": "missing_nonreentrant",
        "name": "Missing nonReentrant Guard",
        "severity": "high",
        "desc": "No reentrancy protection detected. Functions making external calls should use the nonReentrant modifier.",
        "fix": 'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";\ncontract MyContract is ReentrancyGuard { ... }',
    },
    {
        "id": "external_call_before_update",
        "name": "External Call Before State Update (CEI Violation)",
        "severity": "critical",
        "desc": "An external call is made BEFORE state variables are updated. Classic reentrancy: attacker re-enters before balance is decremented.",
        "fix": "// Follow CEI — update state FIRST:\nbalances[msg.sender] -= amount;  // Effect\n(bool ok,) = msg.sender.call{value: amount}(\"\");  // Interact",
    },
    {
        "id": "raw_call_no_guard",
        "name": "Raw .call() Without Guard",
        "severity": "high",
        "desc": "Raw .call() is used without a reentrancy guard. Even if CEI is followed, unguarded calls carry risk.",
        "fix": "Add the nonReentrant modifier from OpenZeppelin's ReentrancyGuard.",
    },
    {
        "id": "send_transfer",
        "name": ".send() / .transfer() Usage",
        "severity": "medium",
        "desc": ".send()/.transfer() forward only 2300 gas. This limits reentrancy but may break with future EVM gas changes (EIP-1884).",
        "fix": '(bool ok,) = recipient.call{value: amount}("");\nrequire(ok, "Transfer failed");',
    },
    {
        "id": "loop_external_call",
        "name": "External Call Inside Loop",
        "severity": "critical",
        "desc": "External calls inside loops are extremely dangerous. Any single iteration can re-enter, and a failed call reverts the entire loop.",
        "fix": "Use Pull Payment pattern:\nLet users withdraw individually instead of pushing to all in a loop.",
    },
    {
        "id": "delegatecall_usage",
        "name": "delegatecall Usage",
        "severity": "medium",
        "desc": "delegatecall runs external code in this contract's storage context. A malicious target can corrupt state or drain funds.",
        "fix": "Only delegatecall to audited contracts. Never to user-supplied addresses.",
    },
    {
        "id": "complex_fallback",
        "name": "Complex receive() / fallback() Logic",
        "severity": "low",
        "desc": "receive() or fallback() contains non-trivial logic. These are triggered during ETH sends and can be exploited in reentrancy chains.",
        "fix": "Keep receive/fallback minimal:\nreceive() external payable {}\n// or just emit an event",
    },
    {
        "id": "cross_function_reentrancy",
        "name": "Cross-Function Reentrancy Risk",
        "severity": "high",
        "desc": "Multiple functions share state variables AND make external calls. An attacker re-entering via a different function can exploit stale state.",
        "fix": "Use nonReentrant on ALL functions that share mutable state with functions making external calls.",
    },
    {
        "id": "ast_cei_violation",
        "name": "AST-Confirmed CEI Violation",
        "severity": "critical",
        "desc": "Solidity compiler AST confirms: an external call node appears before a state assignment node in the same function. This is a verified reentrancy vulnerability.",
        "fix": "Reorder: state update must come before external call in the function body.",
    },
]


# ── Main Analyze Function ────────────────────────────────────

def analyze_contract(code: str) -> dict:
    """
    Full analysis pipeline:
      1. Run solidity_compiler.compile_and_parse() to get
         AST-level contract structure + syntax errors
      2. Run AST-based vulnerability checks (if AST available)
      3. Always run regex checks as a supplemental layer
      4. Merge, deduplicate, score all findings
    """
    lines = code.split("\n")
    line_count = len(lines)
    findings = []

    # ── Step 1: Compile / Parse ──────────────────────────────
    compilation = compile_and_parse(code)

    # ── Step 2: Compiler errors and warnings ────────────────
    compiler_issues = []
    for err in compilation.errors:
        compiler_issues.append({
            "pattern_id": "syntax_error",
            "severity": "error",
            "title": "Syntax Error",
            "line": err.line or 1,
            "desc": err.message,
            "snippet": err.source_location or "",
            "fix": "Fix the syntax error before running security analysis.",
            "source": "solc"
        })
    for warn in compilation.warnings:
        compiler_issues.append({
            "pattern_id": "compiler_warning",
            "severity": "warning",
            "title": "Compiler Warning",
            "line": warn.line or 1,
            "desc": warn.message,
            "snippet": warn.source_location or "",
            "fix": None,
            "source": "solc"
        })

    # ── Step 3: AST-based vulnerability analysis ─────────────
    if compilation.contracts:
        ast_findings = run_ast_analysis(compilation.contracts, code)
        findings.extend(ast_findings)

    # ── Step 4: Regex-based analysis (always runs) ───────────
    regex_findings = run_regex_analysis(code, lines)
    findings.extend(regex_findings)

    # ── Step 5: Deduplicate ───────────────────────────────────
    # Prefer AST findings over regex findings for same line+pattern
    seen = set()
    unique = []
    # AST findings first (they're more accurate)
    for f in sorted(findings, key=lambda x: 0 if x.get("source") == "ast" else 1):
        key = (f["pattern_id"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Add compiler issues at the end
    unique.extend(compiler_issues)

    # ── Step 6: Score ────────────────────────────────────────
    has_guard = any(f["pattern_id"] == "reentrancy_guard_present" for f in unique)
    action_findings = [f for f in unique if f["severity"] not in ("info", "warning")]
    score = calculate_score(action_findings, has_guard)

    # ── Step 7: Summary counts ───────────────────────────────
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
               "warning": 0, "error": 0}
    for f in unique:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1

    return {
        "findings": unique,
        "score": score,
        "summary": summary,
        "line_count": line_count,
        "compiler": {
            "source": compilation.source,
            "version": compilation.version,
            "ast_available": compilation.ast_available,
            "contract_count": len(compilation.contracts),
        }
    }


# ── AST-Based Analysis ───────────────────────────────────────

def run_ast_analysis(contracts: list[ContractInfo], code: str) -> list[dict]:
    """
    Analyze parsed contract structure for reentrancy vulnerabilities.
    This is more accurate than regex because we work with the actual
    parsed representation of the code.
    """
    findings = []
    lines = code.split("\n")

    has_guard_globally = any(
        "ReentrancyGuard" in c.inherits or
        any("nonReentrant" in f.modifiers for f in c.functions)
        for c in contracts
    )

    for contract in contracts:
        has_guard = "ReentrancyGuard" in contract.inherits

        # ── Check: ReentrancyGuard ───────────────────────────
        if has_guard:
            findings.append(_make_finding(
                "reentrancy_guard_present",
                contract.line,
                f"contract {contract.name} is {', '.join(contract.inherits)}",
                source="ast"
            ))
        elif not has_guard_globally:
            findings.append(_make_finding(
                "missing_nonreentrant",
                contract.line,
                f"contract {contract.name} — no ReentrancyGuard inheritance",
                source="ast"
            ))

        # Functions that make external calls (for cross-function check)
        funcs_with_calls = [f for f in contract.functions if f.has_external_call]
        funcs_with_state_and_calls = [
            f for f in funcs_with_calls if f.state_updates_after_call
        ]

        for func in contract.functions:

            # ── Check: CEI Violation (AST-confirmed) ────────
            if func.state_updates_after_call:
                # AST confirmed: call happens before state update
                finding_id = "ast_cei_violation" if func.has_value_transfer else "external_call_before_update"
                findings.append(_make_finding(
                    finding_id,
                    func.external_call_lines[0] if func.external_call_lines else func.line,
                    get_snippet(lines, func.external_call_lines[0] if func.external_call_lines else func.line),
                    source="ast"
                ))

            # ── Check: Raw call without guard ───────────────
            elif func.has_external_call and func.has_value_transfer:
                if "nonReentrant" not in func.modifiers and not has_guard:
                    findings.append(_make_finding(
                        "raw_call_no_guard",
                        func.external_call_lines[0] if func.external_call_lines else func.line,
                        get_snippet(lines, func.external_call_lines[0] if func.external_call_lines else func.line),
                        source="ast"
                    ))

            # ── Check: .send()/.transfer() ───────────────────
            for ln in func.external_call_lines:
                snippet = get_snippet(lines, ln)
                if re.search(r'\.(send|transfer)\s*\(', snippet):
                    findings.append(_make_finding("send_transfer", ln, snippet, source="ast"))

        # ── Check: Cross-function reentrancy ─────────────────
        if len(funcs_with_calls) >= 2:
            # Multiple functions share state AND make calls
            shared_state_funcs = []
            for f in funcs_with_calls:
                if any(sv in '\n'.join(get_snippet(lines, ln) for ln in f.external_call_lines + [f.line])
                       for sv in contract.state_variables):
                    shared_state_funcs.append(f)

            if len(shared_state_funcs) >= 2:
                for f in shared_state_funcs:
                    if "nonReentrant" not in f.modifiers:
                        findings.append(_make_finding(
                            "cross_function_reentrancy",
                            f.line,
                            f"function {f.name}() — shares state with {len(shared_state_funcs)-1} other external-calling function(s)",
                            source="ast"
                        ))

        # ── Check: Complex receive/fallback ──────────────────
        for func in contract.functions:
            if func.name in ("receive", "fallback") and func.has_external_call:
                findings.append(_make_finding(
                    "complex_fallback",
                    func.line,
                    f"{func.name}() external payable — contains external call",
                    source="ast"
                ))

    return findings


# ── Regex-Based Analysis (fallback + supplemental) ──────────

def run_regex_analysis(code: str, lines: list[str]) -> list[dict]:
    """
    Original regex-based scanner. Always runs as a supplemental layer
    to catch anything the AST parser might miss.
    """
    findings = []

    has_guard = bool(re.search(r'ReentrancyGuard|nonReentrant', code))
    has_receive = bool(re.search(r'receive\s*\(\s*\)\s*external', code))
    has_fallback = bool(re.search(r'fallback\s*\(\s*\)\s*external', code))

    CALL_VALUE  = re.compile(r'\.call\s*\{[^}]*value[^}]*\}\s*\(')
    BARE_CALL   = re.compile(r'\w+\.call\s*\(')
    SEND_TRANS  = re.compile(r'\.(send|transfer)\s*\(')
    LOOP_START  = re.compile(r'\b(for|while)\s*\(')
    DELEGATECALL= re.compile(r'\.delegatecall\s*\(')

    # ── ReentrancyGuard ──────────────────────────────────────
    if has_guard:
        ln = find_line(lines, re.compile(r'ReentrancyGuard|nonReentrant'))
        findings.append(_make_finding("reentrancy_guard_present", ln or 1,
            get_snippet(lines, ln or 1), source="regex"))
    else:
        findings.append(_make_finding("missing_nonreentrant", 1,
            "// No ReentrancyGuard found", source="regex"))

    # ── CEI Violation ────────────────────────────────────────
    call_lines = find_all_lines(lines, CALL_VALUE)
    for ln in call_lines:
        update_after = any(
            looks_like_state_update(lines[i])
            for i in range(ln, min(ln + 10, len(lines)))
        )
        if update_after:
            findings.append(_make_finding(
                "external_call_before_update", ln,
                get_snippet(lines, ln), source="regex"))
        elif not has_guard:
            findings.append(_make_finding(
                "raw_call_no_guard", ln,
                get_snippet(lines, ln), source="regex"))

    # ── send / transfer ──────────────────────────────────────
    for ln in find_all_lines(lines, SEND_TRANS):
        findings.append(_make_finding("send_transfer", ln,
            get_snippet(lines, ln), source="regex"))

    # ── Loop with external call ──────────────────────────────
    in_loop = False
    depth = 0
    for i, line in enumerate(lines):
        ln = i + 1
        if LOOP_START.search(line):
            in_loop = True; depth = 0
        if in_loop:
            depth += line.count("{"); depth -= line.count("}")
            if depth <= 0: in_loop = False
            elif CALL_VALUE.search(line) or SEND_TRANS.search(line):
                findings.append(_make_finding("loop_external_call", ln,
                    get_snippet(lines, ln), source="regex"))

    # ── delegatecall ────────────────────────────────────────
    for ln in find_all_lines(lines, DELEGATECALL):
        findings.append(_make_finding("delegatecall_usage", ln,
            get_snippet(lines, ln), source="regex"))

    # ── Complex receive/fallback ─────────────────────────────
    if has_receive or has_fallback:
        pat = re.compile(r'(receive|fallback)\s*\(\s*\)\s*external')
        ln = find_line(lines, pat)
        if ln:
            body = "\n".join(lines[ln:min(ln+15, len(lines))])
            if re.search(r'\b(if|for|while|call|transfer|balances)\b', body):
                findings.append(_make_finding("complex_fallback", ln,
                    get_snippet(lines, ln), source="regex"))

    return findings


# ── Helpers ──────────────────────────────────────────────────

def _make_finding(pattern_id: str, line: int, snippet: str, source: str = "regex") -> dict:
    pat = next((p for p in VULNERABILITY_PATTERNS if p["id"] == pattern_id), None)
    if not pat:
        return {}
    return {
        "pattern_id": pattern_id,
        "severity":   pat["severity"],
        "title":      pat["name"],
        "line":       line,
        "desc":       pat["desc"],
        "snippet":    snippet,
        "fix":        pat["fix"],
        "source":     source,  # 'ast' | 'regex'
    }

def get_snippet(lines: list[str], ln: int) -> str:
    if 1 <= ln <= len(lines):
        return lines[ln - 1].strip()
    return ""

def find_line(lines: list[str], pattern: re.Pattern) -> int | None:
    for i, line in enumerate(lines):
        if pattern.search(line):
            return i + 1
    return None

def find_all_lines(lines: list[str], pattern: re.Pattern) -> list[int]:
    return [i + 1 for i, line in enumerate(lines) if pattern.search(line)]

def looks_like_state_update(line: str) -> bool:
    has_assign = bool(re.search(r'\w+\s*[\-\+\*\/]?=(?!=)', line))
    not_condition = not re.search(r'\b(require|bool|address|return|emit|if)\b', line)
    return has_assign and not_condition

def calculate_score(findings: list[dict], has_guard: bool) -> int:
    score = 100
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "error": 10}
    for f in findings:
        score -= weights.get(f.get("severity", "low"), 0)
    if has_guard:
        score += 10
    return max(0, min(100, score))
