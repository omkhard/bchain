# ============================================================
#  scanner.py  —  The vulnerability detection engine
# ============================================================
#
#  This file contains ALL the scanning logic.
#  It is pure Python — no Flask, no web stuff.
#  This separation is intentional:
#    • app.py  handles HTTP (web layer)
#    • scanner.py  handles logic (business layer)
#
#  You could run analyze_contract() from a CLI script,
#  a test file, or a different web framework — it doesn't care.
#
# ============================================================

import re   # Python's built-in Regular Expression module


# ── Vulnerability Pattern Definitions ───────────────────────
#
# Each pattern is a dictionary describing ONE type of vulnerability.
# The scanner loops through all of them and checks the contract.
#
# Fields:
#   id        — unique machine-readable name
#   name      — human-readable name shown in the UI
#   severity  — critical | high | medium | low | info
#   desc      — explanation of why this is dangerous
#   fix       — recommended fix (shown in UI)

VULNERABILITY_PATTERNS = [
    {
        "id": "reentrancy_guard_present",
        "name": "ReentrancyGuard Present",
        "severity": "info",
        "desc": "OpenZeppelin ReentrancyGuard is imported or nonReentrant modifier is used. This is a good protective measure.",
        "fix": None,
    },
    {
        "id": "missing_nonreentrant",
        "name": "Missing nonReentrant Guard",
        "severity": "high",
        "desc": "No reentrancy protection detected. Functions that make external calls should use the nonReentrant modifier.",
        "fix": 'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";\ncontract MyContract is ReentrancyGuard { ... }',
    },
    {
        "id": "external_call_before_update",
        "name": "External Call Before State Update",
        "severity": "critical",
        "desc": (
            "A .call{value}() is made BEFORE state variables are updated. "
            "This is the classic reentrancy pattern. An attacker can re-enter "
            "this function before the balance is decremented, draining the contract."
        ),
        "fix": (
            "// Follow the CEI pattern — update state FIRST:\n"
            "balances[msg.sender] -= amount;  // Effect first\n"
            '(bool ok,) = msg.sender.call{value: amount}("");  // Interact last'
        ),
    },
    {
        "id": "raw_call",
        "name": "Raw .call() Without Guard",
        "severity": "high",
        "desc": "Raw .call() is used without a reentrancy guard. Even if CEI is followed, unguarded calls are risky.",
        "fix": "Add the nonReentrant modifier and verify the CEI pattern is strictly followed.",
    },
    {
        "id": "send_transfer",
        "name": ".send() / .transfer() Usage",
        "severity": "medium",
        "desc": (
            ".send() and .transfer() forward only 2300 gas, which limits reentrancy "
            "but may break with future EVM gas cost changes (EIP-1884). "
            "Modern contracts prefer .call{value}() with proper guards."
        ),
        "fix": '(bool ok,) = recipient.call{value: amount}("");\nrequire(ok, "Transfer failed");',
    },
    {
        "id": "loop_external",
        "name": "External Call Inside Loop",
        "severity": "critical",
        "desc": (
            "Making external calls inside a loop is extremely dangerous. "
            "Each iteration can be re-entered, and if any call fails, "
            "the entire loop reverts — potentially bricking the function."
        ),
        "fix": (
            "Use the Pull Payment (withdrawal) pattern:\n"
            "Let users withdraw their own funds individually\n"
            "instead of pushing to all users in a loop."
        ),
    },
    {
        "id": "delegatecall",
        "name": "delegatecall Usage",
        "severity": "medium",
        "desc": (
            "delegatecall executes external code in this contract's context, "
            "sharing storage and ETH balance. If the called contract is malicious, "
            "it can corrupt storage or drain funds."
        ),
        "fix": "Only delegatecall to thoroughly audited contracts. Never to user-supplied addresses.",
    },
    {
        "id": "fallback_logic",
        "name": "Complex Fallback / receive() Logic",
        "severity": "low",
        "desc": (
            "receive() or fallback() contains non-trivial logic. "
            "These functions are triggered during ETH sends and can be "
            "exploited in reentrancy attack chains."
        ),
        "fix": "Keep receive/fallback minimal:\nreceive() external payable {}\n// Or just emit an event.",
    },
]


# ── Helper Functions ─────────────────────────────────────────

def find_line_number(lines: list[str], pattern: re.Pattern) -> int | None:
    """
    Return the 1-based line number of the FIRST line matching pattern.
    Returns None if not found.

    Example:
        lines = ["pragma solidity...", "contract Foo {", "function bar()..."]
        find_line_number(lines, re.compile(r"function bar")) → 3
    """
    for i, line in enumerate(lines):
        if pattern.search(line):
            return i + 1   # +1 because humans count lines from 1, not 0
    return None


def find_all_line_numbers(lines: list[str], pattern: re.Pattern) -> list[int]:
    """
    Return a list of ALL 1-based line numbers matching pattern.

    Example:
        If ".call{value}" appears on lines 12, 45, 78
        this returns [12, 45, 78]
    """
    return [i + 1 for i, line in enumerate(lines) if pattern.search(line)]


def get_snippet(lines: list[str], line_number: int) -> str:
    """
    Return the actual source code at line_number (1-based).
    Strips leading/trailing whitespace.
    """
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def looks_like_state_update(line: str) -> bool:
    """
    Heuristic: does this line look like a Solidity state variable assignment?

    We look for patterns like:
        balances[msg.sender] -= amount;
        totalSupply = 0;
        owner = newOwner;

    We exclude lines with:  require, bool, address, return
    because those often contain = but aren't state updates.
    """
    has_assignment = bool(re.search(r'\w+\s*[\-\+\*\/]?=', line))
    is_not_condition = not re.search(r'\b(require|bool|address|return|emit)\b', line)
    return has_assignment and is_not_condition


# ── Main Scanner Function ────────────────────────────────────

def analyze_contract(code: str) -> dict:
    """
    Analyze a Solidity contract string for reentrancy vulnerabilities.

    Parameters:
        code (str): Raw Solidity source code

    Returns:
        dict: {
            "findings":  list of finding dicts,
            "score":     int  (0–100),
            "summary":   dict with counts per severity,
            "line_count": int
        }

    This is the main entry point called by app.py.
    """

    # Split code into individual lines for line-by-line analysis
    lines = code.split("\n")
    line_count = len(lines)

    # This list will collect all detected issues
    findings = []

    # ── Pre-checks ──────────────────────────────────────────
    # Some things we just need to know about the whole contract

    has_reentrancy_guard = bool(
        re.search(r'ReentrancyGuard', code) or
        re.search(r'nonReentrant', code)
    )

    has_receive = bool(re.search(r'receive\s*\(\s*\)\s*external', code))
    has_fallback = bool(re.search(r'fallback\s*\(\s*\)\s*external', code))

    # Regex patterns we'll reuse
    CALL_WITH_VALUE = re.compile(r'\.call\s*\{[^}]*value[^}]*\}\s*\(')
    BARE_CALL       = re.compile(r'\w+\.call\s*\(')
    SEND_TRANSFER   = re.compile(r'\.(send|transfer)\s*\(')
    LOOP_START      = re.compile(r'\b(for|while)\s*\(')
    DELEGATECALL    = re.compile(r'\.delegatecall\s*\(')

    # ── Check 1: ReentrancyGuard ────────────────────────────
    if has_reentrancy_guard:
        ln = (find_line_number(lines, re.compile(r'ReentrancyGuard')) or
              find_line_number(lines, re.compile(r'nonReentrant')))
        findings.append(_make_finding(
            pattern_id="reentrancy_guard_present",
            line=ln or 1,
            snippet=get_snippet(lines, ln or 1),
        ))
    else:
        findings.append(_make_finding(
            pattern_id="missing_nonreentrant",
            line=1,
            snippet="// No ReentrancyGuard found in contract",
        ))

    # ── Check 2: External calls before state updates ────────
    #
    # Algorithm:
    #   1. Find every line with .call{value}()
    #   2. For each such line, look at the next 10 lines
    #   3. If any of those lines looks like a state update → CRITICAL
    #
    call_value_lines = find_all_line_numbers(lines, CALL_WITH_VALUE)

    for ln in call_value_lines:
        update_after = False
        # Check the 10 lines AFTER the .call()
        for lookahead in range(ln, min(ln + 10, line_count)):
            if looks_like_state_update(lines[lookahead]):
                update_after = True
                break

        if update_after:
            findings.append(_make_finding(
                pattern_id="external_call_before_update",
                line=ln,
                snippet=get_snippet(lines, ln),
            ))
        elif not has_reentrancy_guard:
            # .call{value} without guard, even if CEI looks ok
            findings.append(_make_finding(
                pattern_id="raw_call",
                line=ln,
                snippet=get_snippet(lines, ln),
            ))

    # ── Check 3: .send() and .transfer() ───────────────────
    for ln in find_all_line_numbers(lines, SEND_TRANSFER):
        findings.append(_make_finding(
            pattern_id="send_transfer",
            line=ln,
            snippet=get_snippet(lines, ln),
        ))

    # ── Check 4: External calls inside loops ────────────────
    #
    # Algorithm:
    #   Track whether we're inside a for/while loop by counting
    #   opening { and closing } braces.
    #
    in_loop = False
    brace_depth = 0

    for i, line in enumerate(lines):
        ln = i + 1  # 1-based line number

        # Detect loop start
        if LOOP_START.search(line):
            in_loop = True
            brace_depth = 0

        if in_loop:
            brace_depth += line.count("{")
            brace_depth -= line.count("}")

            # If braces are balanced back to 0, we've exited the loop
            if brace_depth <= 0:
                in_loop = False

            # Flag any external call found inside the loop
            elif CALL_WITH_VALUE.search(line) or SEND_TRANSFER.search(line):
                findings.append(_make_finding(
                    pattern_id="loop_external",
                    line=ln,
                    snippet=get_snippet(lines, ln),
                ))

    # ── Check 5: delegatecall ───────────────────────────────
    for ln in find_all_line_numbers(lines, DELEGATECALL):
        findings.append(_make_finding(
            pattern_id="delegatecall",
            line=ln,
            snippet=get_snippet(lines, ln),
        ))

    # ── Check 6: Complex receive() / fallback() ─────────────
    if has_receive or has_fallback:
        pattern = re.compile(r'(receive|fallback)\s*\(\s*\)\s*external')
        ln = find_line_number(lines, pattern)

        if ln:
            # Grab the next 15 lines after the function declaration
            body = "\n".join(lines[ln : ln + 15])
            # Does the body have any non-trivial logic?
            if re.search(r'\b(if|for|while|call|transfer|balances|mapping)\b', body):
                findings.append(_make_finding(
                    pattern_id="fallback_logic",
                    line=ln,
                    snippet=get_snippet(lines, ln),
                ))

    # ── Deduplicate ─────────────────────────────────────────
    # Same pattern on the same line shouldn't appear twice
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["pattern_id"], f["line"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # ── Calculate score ─────────────────────────────────────
    action_findings = [f for f in unique_findings if f["severity"] != "info"]
    score = calculate_score(action_findings, has_reentrancy_guard)

    # ── Build summary counts ─────────────────────────────────
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in unique_findings:
        summary[f["severity"]] += 1

    return {
        "findings": unique_findings,
        "score": score,
        "summary": summary,
        "line_count": line_count,
    }


def _make_finding(pattern_id: str, line: int, snippet: str) -> dict:
    """
    Build a finding dict by looking up the pattern definition.

    This keeps the scanner checks clean — they just say which pattern
    was detected and where, and this function fills in all the details.
    """
    # Find the matching pattern definition
    pattern_def = next(
        (p for p in VULNERABILITY_PATTERNS if p["id"] == pattern_id),
        None
    )

    if not pattern_def:
        raise ValueError(f"Unknown pattern_id: {pattern_id}")

    return {
        "pattern_id": pattern_id,
        "severity":   pattern_def["severity"],
        "title":      pattern_def["name"],
        "line":       line,
        "desc":       pattern_def["desc"],
        "snippet":    snippet,
        "fix":        pattern_def["fix"],
    }


def calculate_score(findings: list[dict], has_guard: bool) -> int:
    """
    Calculate a security score from 0 to 100.

    Deductions:
        critical  → -25 points each
        high      → -15 points each
        medium    →  -8 points each
        low       →  -3 points each

    Bonus:
        ReentrancyGuard present → +10 points

    Final score is clamped to [0, 100].
    """
    score = 100

    deductions = {
        "critical": 25,
        "high":     15,
        "medium":    8,
        "low":       3,
    }

    for finding in findings:
        severity = finding.get("severity", "low")
        score -= deductions.get(severity, 0)

    if has_guard:
        score += 10

    # Clamp to valid range
    return max(0, min(100, score))
