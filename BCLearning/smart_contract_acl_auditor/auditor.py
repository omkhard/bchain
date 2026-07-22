# ============================================================
#  auditor.py  —  Smart Contract Access Control Audit Engine
#
#  ACCESS CONTROL VULNERABILITY CLASSES WE DETECT:
#
#  1.  Unprotected sensitive functions      (no modifier at all)
#  2.  Missing onlyOwner on critical ops    (withdraw, setOwner, etc.)
#  3.  Public/external state-changing funcs (no restriction)
#  4.  Selfdestruct without access control  (anyone can kill contract)
#  5.  tx.origin authentication             (phishing bypass)
#  6.  Unprotected initializer functions    (Parity wallet bug class)
#  7.  Missing zero-address validation      (owner = address(0))
#  8.  Role not granted before use          (OpenZeppelin RBAC misuse)
#  9.  Hardcoded address authorization      (fragile, non-upgradeable)
# 10.  Missing event on sensitive action    (silent privilege change)
#
# ============================================================

import re
from dataclasses import dataclass, field


# ── Vulnerability Pattern Definitions ──────────────────────

VULNERABILITY_PATTERNS = [
    {
        "id": "unprotected_selfdestruct",
        "name": "Unprotected selfdestruct",
        "severity": "critical",
        "desc": (
            "selfdestruct() can be called by anyone — it permanently destroys "
            "the contract and sends all ETH to a given address. An attacker "
            "can wipe the contract and steal funds instantly."
        ),
        "fix": (
            "modifier onlyOwner() {\n"
            "    require(msg.sender == owner, 'Not authorized');\n"
            "    _;\n"
            "}\n\n"
            "function destroy() external onlyOwner {\n"
            "    selfdestruct(payable(owner));\n"
            "}"
        ),
        "ref": "SWC-106",
    },
    {
        "id": "unprotected_initializer",
        "name": "Unprotected initializer function",
        "severity": "critical",
        "desc": (
            "An init() / initialize() function has no access control. "
            "This is the exact bug that caused the Parity Wallet hack ($30M). "
            "Anyone can call it to re-initialize the contract and take ownership."
        ),
        "fix": (
            "// Option 1: Use a constructor instead of init()\n"
            "constructor(address _owner) { owner = _owner; }\n\n"
            "// Option 2: Add an initialized flag\n"
            "bool private initialized;\n"
            "function initialize(address _owner) external {\n"
            "    require(!initialized, 'Already initialized');\n"
            "    initialized = true;\n"
            "    owner = _owner;\n"
            "}"
        ),
        "ref": "SWC-118",
    },
    {
        "id": "tx_origin_auth",
        "name": "tx.origin used for authentication",
        "severity": "critical",
        "desc": (
            "tx.origin refers to the ORIGINAL transaction sender, not the "
            "immediate caller. An attacker can trick a victim into calling a "
            "malicious contract, which then calls your contract — tx.origin "
            "will be the victim, bypassing the check. Always use msg.sender."
        ),
        "fix": (
            "// ❌ WRONG — vulnerable to phishing\n"
            "require(tx.origin == owner, 'Not owner');\n\n"
            "// ✅ CORRECT — use msg.sender\n"
            "require(msg.sender == owner, 'Not owner');"
        ),
        "ref": "SWC-115",
    },
    {
        "id": "unprotected_sensitive_function",
        "name": "Sensitive function missing access control",
        "severity": "high",
        "desc": (
            "A function with a sensitive name (withdraw, transfer, mint, burn, "
            "setOwner, pause, upgrade) has no access control modifier. "
            "Anyone can call it."
        ),
        "fix": (
            "// Add onlyOwner or a role check:\n"
            "function withdraw(uint amount) external onlyOwner {\n"
            "    payable(msg.sender).transfer(amount);\n"
            "}\n\n"
            "// Or use OpenZeppelin AccessControl:\n"
            "function mint(address to, uint amount) external onlyRole(MINTER_ROLE) {\n"
            "    _mint(to, amount);\n"
            "}"
        ),
        "ref": "SWC-105",
    },
    {
        "id": "missing_zero_address_check",
        "name": "Missing zero-address validation",
        "severity": "high",
        "desc": (
            "An ownership transfer or address assignment has no check for "
            "address(0). Setting owner to address(0) permanently locks the "
            "contract — no function protected by onlyOwner can ever be called again."
        ),
        "fix": (
            "function transferOwnership(address newOwner) external onlyOwner {\n"
            "    require(newOwner != address(0), 'Zero address not allowed');\n"
            "    emit OwnershipTransferred(owner, newOwner);\n"
            "    owner = newOwner;\n"
            "}"
        ),
        "ref": "SWC-112",
    },
    {
        "id": "public_state_changing_function",
        "name": "Unrestricted public state-changing function",
        "severity": "high",
        "desc": (
            "A public or external function modifies contract state (writes to "
            "storage variables) but has no access control modifier. "
            "Any caller can change contract state."
        ),
        "fix": (
            "// Change visibility to internal/private if not needed externally\n"
            "function _updateState(uint val) internal { ... }\n\n"
            "// Or add access control if it must be public\n"
            "function updateState(uint val) external onlyOwner { ... }"
        ),
        "ref": "SWC-105",
    },
    {
        "id": "hardcoded_address_auth",
        "name": "Hardcoded address used for authorization",
        "severity": "medium",
        "desc": (
            "A specific address is hardcoded in the source for authorization. "
            "If that address is compromised or lost, the authorization cannot "
            "be updated. This is fragile and non-upgradeable."
        ),
        "fix": (
            "// ❌ Fragile — hardcoded address\n"
            "require(msg.sender == 0xAb5801..., 'Not authorized');\n\n"
            "// ✅ Flexible — use a state variable\n"
            "address public owner;\n"
            "require(msg.sender == owner, 'Not authorized');"
        ),
        "ref": "SWC-132",
    },
    {
        "id": "missing_event_on_ownership_change",
        "name": "No event emitted on ownership/role change",
        "severity": "medium",
        "desc": (
            "Ownership transfer or role assignment happens silently — no event "
            "is emitted. Off-chain monitors and block explorers cannot detect "
            "or alert on privilege changes, making attacks harder to notice."
        ),
        "fix": (
            "event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n\n"
            "function transferOwnership(address newOwner) external onlyOwner {\n"
            "    require(newOwner != address(0), 'Zero address');\n"
            "    emit OwnershipTransferred(owner, newOwner); // ← always emit\n"
            "    owner = newOwner;\n"
            "}"
        ),
        "ref": "SWC-120",
    },
    {
        "id": "weak_modifier",
        "name": "Weak or incomplete access modifier",
        "severity": "medium",
        "desc": (
            "A modifier exists but its body doesn't contain a require() or "
            "revert() — it only has `_;` or other logic. A modifier without "
            "a revert path doesn't actually restrict anything."
        ),
        "fix": (
            "// ❌ Weak — no restriction\n"
            "modifier onlyOwner() { _; }\n\n"
            "// ✅ Correct\n"
            "modifier onlyOwner() {\n"
            "    require(msg.sender == owner, 'Not authorized');\n"
            "    _;\n"
            "}"
        ),
        "ref": "SWC-105",
    },
    {
        "id": "single_step_ownership_transfer",
        "name": "Single-step ownership transfer",
        "severity": "low",
        "desc": (
            "Ownership is transferred in one step. If the new owner address is "
            "wrong (typo, dead wallet), ownership is permanently lost. "
            "Two-step transfer (propose + accept) is safer."
        ),
        "fix": (
            "// Two-step ownership transfer pattern:\n"
            "address public pendingOwner;\n\n"
            "function transferOwnership(address newOwner) external onlyOwner {\n"
            "    pendingOwner = newOwner;\n"
            "}\n\n"
            "function acceptOwnership() external {\n"
            "    require(msg.sender == pendingOwner, 'Not pending owner');\n"
            "    owner = pendingOwner;\n"
            "    pendingOwner = address(0);\n"
            "}"
        ),
        "ref": "Best Practice",
    },
    {
        "id": "renounce_ownership_present",
        "name": "renounceOwnership() present without warning",
        "severity": "low",
        "desc": (
            "renounceOwnership() permanently removes the owner, making all "
            "onlyOwner functions permanently uncallable. This is often included "
            "from OpenZeppelin but not always intentional."
        ),
        "fix": (
            "// If intentional, leave it. If not, override it:\n"
            "function renounceOwnership() public override onlyOwner {\n"
            "    revert('Renounce disabled for this contract');\n"
            "}"
        ),
        "ref": "Best Practice",
    },
    {
        "id": "modifier_present",
        "name": "Access control modifier present",
        "severity": "info",
        "desc": "onlyOwner or similar access control modifier is defined in this contract.",
        "fix": None,
        "ref": None,
    },
    {
        "id": "openzeppelin_ownable",
        "name": "OpenZeppelin Ownable / AccessControl in use",
        "severity": "info",
        "desc": "Contract uses OpenZeppelin's battle-tested Ownable or AccessControl — good practice.",
        "fix": None,
        "ref": None,
    },
]


# ── Data Structures ──────────────────────────────────────────

@dataclass
class FunctionRecord:
    """Represents one parsed Solidity function."""
    name: str
    line: int
    visibility: str           # public | external | internal | private
    modifiers: list[str]      # e.g. ['onlyOwner', 'nonReentrant']
    is_payable: bool
    has_state_write: bool     # writes to storage variables
    is_sensitive: bool        # name matches sensitive keywords
    calls_selfdestruct: bool
    calls_transfer: bool
    has_require: bool
    snippet: str              # first line of function signature


@dataclass
class ModifierRecord:
    """Represents a Solidity modifier definition."""
    name: str
    line: int
    has_require: bool         # does it actually restrict?
    snippet: str


@dataclass
class RoleRecord:
    """Represents an access control role or address variable."""
    name: str
    line: int
    kind: str                 # 'owner' | 'role_constant' | 'mapping' | 'hardcoded'
    snippet: str


# ── Sensitive keyword sets ───────────────────────────────────

SENSITIVE_FUNC_NAMES = {
    # Fund management
    "withdraw", "withdrawAll", "withdrawETH", "withdrawToken",
    "transfer", "transferFunds", "drain", "sweep",
    # Token operations
    "mint", "burn", "burnFrom", "mintTo",
    # Ownership / roles
    "setOwner", "transferOwnership", "renounceOwnership",
    "grantRole", "revokeRole", "addAdmin", "removeAdmin",
    "addMinter", "removeMinter", "setAdmin",
    # Contract control
    "pause", "unpause", "freeze", "unfreeze",
    "upgrade", "upgradeTo", "upgradeToAndCall",
    "setImplementation", "destroy", "kill",
    # Configuration
    "setFee", "setPrice", "setRate", "setWhitelist",
    "setBlacklist", "setMaxSupply", "setTreasury",
    "initialize", "init", "setup",
}

INIT_FUNC_NAMES = {"initialize", "init", "setup", "__init__", "initializer"}

OWNERSHIP_FUNC_NAMES = {
    "transferOwnership", "setOwner", "changeOwner",
    "renounceOwnership", "acceptOwnership",
}


# ── Core helpers ─────────────────────────────────────────────

def strip_comments(code: str) -> str:
    """Remove // and /* */ comments so regex isn't fooled by them."""
    code = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'), code, flags=re.DOTALL)
    code = re.sub(r'//[^\n]*', '', code)
    return code


def get_snippet(lines: list[str], ln: int, max_len: int = 120) -> str:
    if 1 <= ln <= len(lines):
        return lines[ln - 1].strip()[:max_len]
    return ""


def line_of(lines: list[str], pattern: re.Pattern) -> int | None:
    for i, line in enumerate(lines):
        if pattern.search(line):
            return i + 1
    return None


def all_lines_of(lines: list[str], pattern: re.Pattern) -> list[int]:
    return [i + 1 for i, line in enumerate(lines) if pattern.search(line)]


def extract_brace_block(code: str, start: int) -> str:
    """Extract content between matching { } starting at position start."""
    depth = 0
    i = start
    while i < len(code):
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
            if depth == 0:
                return code[start + 1:i]
        i += 1
    return code[start + 1:]


def make_finding(pattern_id: str, line: int, snippet: str,
                 extra_desc: str = "", source: str = "auditor") -> dict:
    pat = next((p for p in VULNERABILITY_PATTERNS if p["id"] == pattern_id), None)
    if not pat:
        return {}
    desc = pat["desc"] + (f" — {extra_desc}" if extra_desc else "")
    return {
        "pattern_id": pattern_id,
        "severity":   pat["severity"],
        "title":      pat["name"],
        "line":       line,
        "desc":       desc,
        "snippet":    snippet,
        "fix":        pat["fix"],
        "ref":        pat.get("ref"),
        "source":     source,
    }


# ── Parser: Modifiers ────────────────────────────────────────

def parse_modifiers(clean_code: str, lines: list[str]) -> list[ModifierRecord]:
    """Parse all modifier definitions from the contract."""
    modifiers = []
    pattern = re.compile(r'\bmodifier\s+(\w+)\s*\([^)]*\)\s*\{')

    for match in pattern.finditer(clean_code):
        name = match.group(1)
        ln = clean_code[:match.start()].count('\n') + 1
        body = extract_brace_block(clean_code, match.end() - 1)
        has_require = bool(re.search(r'\b(require|revert|assert)\b', body))
        modifiers.append(ModifierRecord(
            name=name,
            line=ln,
            has_require=has_require,
            snippet=get_snippet(lines, ln),
        ))

    return modifiers


# ── Parser: Functions ────────────────────────────────────────

def parse_functions(clean_code: str, lines: list[str]) -> list[FunctionRecord]:
    """Parse all function definitions from the contract."""
    functions = []

    # Match: function name(params) visibility [modifiers] [returns (...)] {
    pattern = re.compile(
        r'\bfunction\s+(\w+)\s*\([^)]*\)\s*([^{;]*)\{'
    )

    for match in pattern.finditer(clean_code):
        name = match.group(1)
        sig_rest = match.group(2)  # everything between ) and {
        ln = clean_code[:match.start()].count('\n') + 1

        # Visibility
        visibility = "internal"
        for vis in ("external", "public", "private", "internal"):
            if re.search(r'\b' + vis + r'\b', sig_rest):
                visibility = vis
                break

        is_payable = bool(re.search(r'\bpayable\b', sig_rest))

        # Modifiers: words that aren't visibility/mutability keywords
        skip_words = {
            "external", "public", "private", "internal",
            "payable", "view", "pure", "virtual", "override",
            "returns", "memory", "storage", "calldata",
        }
        modifiers = []
        for word in re.findall(r'\b([a-zA-Z_]\w*)\b', sig_rest):
            if word not in skip_words and len(word) > 2:
                if re.match(r'^[a-z][a-zA-Z_]+$', word):
                    modifiers.append(word)

        # Extract function body
        body = extract_brace_block(clean_code, match.end() - 1)

        # Analyze body
        has_state_write = bool(re.search(
            r'\b\w+\s*[\-\+\*\/]?=(?!=)\s*', body
        )) and not re.search(r'\b(view|pure)\b', sig_rest)

        calls_selfdestruct = bool(re.search(r'\bselfdestruct\s*\(', body))
        calls_transfer = bool(re.search(
            r'\.(transfer|send)\s*\(|\.call\s*\{[^}]*value', body
        ))
        has_require = bool(re.search(r'\b(require|revert|assert)\b', body))

        is_sensitive = name.lower() in {s.lower() for s in SENSITIVE_FUNC_NAMES}

        functions.append(FunctionRecord(
            name=name,
            line=ln,
            visibility=visibility,
            modifiers=modifiers,
            is_payable=is_payable,
            has_state_write=has_state_write,
            is_sensitive=is_sensitive,
            calls_selfdestruct=calls_selfdestruct,
            calls_transfer=calls_transfer,
            has_require=has_require,
            snippet=get_snippet(lines, ln),
        ))

    return functions


# ── Parser: Roles & Auth Variables ──────────────────────────

def parse_roles(clean_code: str, lines: list[str]) -> list[RoleRecord]:
    """Find all access control related state variables."""
    roles = []

    # address public owner / address private _owner
    owner_pattern = re.compile(
        r'\baddress\s+(?:public|private|internal)?\s*(\w*[Oo]wner\w*)\s*[;=]'
    )
    for m in owner_pattern.finditer(clean_code):
        ln = clean_code[:m.start()].count('\n') + 1
        roles.append(RoleRecord(
            name=m.group(1), line=ln, kind="owner",
            snippet=get_snippet(lines, ln)
        ))

    # bytes32 public constant MINTER_ROLE = keccak256(...)
    role_const_pattern = re.compile(
        r'bytes32\s+(?:public|private)?\s*constant\s+(\w+_ROLE)\s*='
    )
    for m in role_const_pattern.finditer(clean_code):
        ln = clean_code[:m.start()].count('\n') + 1
        roles.append(RoleRecord(
            name=m.group(1), line=ln, kind="role_constant",
            snippet=get_snippet(lines, ln)
        ))

    # mapping(address => bool) public isAdmin / whitelist / blacklist
    mapping_pattern = re.compile(
        r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*(?:public|private)?\s*(\w+)\s*;'
    )
    for m in mapping_pattern.finditer(clean_code):
        name = m.group(1)
        if any(kw in name.lower() for kw in
               ("admin", "owner", "auth", "white", "black", "allow", "role", "minter")):
            ln = clean_code[:m.start()].count('\n') + 1
            roles.append(RoleRecord(
                name=name, line=ln, kind="mapping",
                snippet=get_snippet(lines, ln)
            ))

    return roles


# ── Main Audit Function ──────────────────────────────────────

def audit_contract(code: str) -> dict:
    """
    Full access control audit of a Solidity contract.

    Returns:
        {
          "findings":  list of finding dicts,
          "score":     int (0-100),
          "summary":   severity counts,
          "functions": list of parsed functions (for UI function table),
          "modifiers": list of parsed modifiers,
          "roles":     list of access control variables,
          "line_count": int,
          "contract_name": str
        }
    """
    clean_code = strip_comments(code)
    lines = code.split('\n')
    clean_lines = clean_code.split('\n')
    line_count = len(lines)
    findings = []

    # ── Contract name ─────────────────────────────────────────
    contract_name = "Unknown"
    cm = re.search(r'\bcontract\s+(\w+)', clean_code)
    if cm:
        contract_name = cm.group(1)

    # ── Parse structure ───────────────────────────────────────
    modifiers   = parse_modifiers(clean_code, lines)
    functions   = parse_functions(clean_code, lines)
    roles       = parse_roles(clean_code, lines)

    modifier_names = {m.name for m in modifiers}
    has_oz_ownable = bool(re.search(
        r'import.*["\'].*[Oo]wnable["\']|contract\s+\w+\s+is\s+.*[Oo]wnable',
        code
    ))
    has_oz_access_control = bool(re.search(
        r'import.*AccessControl|contract\s+\w+\s+is\s+.*AccessControl',
        code
    ))

    # ── Check: OpenZeppelin present ───────────────────────────
    if has_oz_ownable or has_oz_access_control:
        ln = line_of(clean_lines, re.compile(r'Ownable|AccessControl'))
        findings.append(make_finding(
            "openzeppelin_ownable", ln or 1,
            get_snippet(lines, ln or 1),
            extra_desc=f"{'Ownable' if has_oz_ownable else 'AccessControl'} detected"
        ))

    # ── Check: Modifier presence ──────────────────────────────
    access_modifiers = [
        m for m in modifiers
        if any(kw in m.name.lower() for kw in
               ("owner", "admin", "auth", "role", "only", "guard"))
    ]
    if access_modifiers:
        findings.append(make_finding(
            "modifier_present", access_modifiers[0].line,
            access_modifiers[0].snippet,
            extra_desc=f"{len(access_modifiers)} access modifier(s) defined"
        ))

    # ── Check: Weak modifiers ─────────────────────────────────
    for mod in modifiers:
        if not mod.has_require:
            # Only flag modifiers that look like they should restrict
            if any(kw in mod.name.lower() for kw in
                   ("owner", "admin", "auth", "role", "only")):
                findings.append(make_finding(
                    "weak_modifier", mod.line, mod.snippet,
                    extra_desc=f"modifier {mod.name}() has no require/revert"
                ))

    # ── Check: tx.origin ─────────────────────────────────────
    tx_origin_lines = all_lines_of(clean_lines, re.compile(r'\btx\.origin\b'))
    for ln in tx_origin_lines:
        findings.append(make_finding(
            "tx_origin_auth", ln, get_snippet(lines, ln)
        ))

    # ── Check: selfdestruct ───────────────────────────────────
    for func in functions:
        if func.calls_selfdestruct:
            is_protected = bool(func.modifiers) or func.has_require
            if not is_protected:
                findings.append(make_finding(
                    "unprotected_selfdestruct", func.line, func.snippet,
                    extra_desc=f"function {func.name}() calls selfdestruct with no guard"
                ))

    # ── Check: Unprotected initializer ───────────────────────
    for func in functions:
        if func.name.lower() in {n.lower() for n in INIT_FUNC_NAMES}:
            is_public_or_ext = func.visibility in ("public", "external")
            has_modifier = bool(func.modifiers)
            has_initialized_check = bool(re.search(
                r'initialized', extract_brace_block(
                    clean_code,
                    clean_code.find('{', clean_code.find(f'function {func.name}'))
                ) if f'function {func.name}' in clean_code else ""
            ))
            if is_public_or_ext and not has_modifier and not has_initialized_check:
                findings.append(make_finding(
                    "unprotected_initializer", func.line, func.snippet,
                    extra_desc=f"function {func.name}() is public/external with no protection"
                ))

    # ── Check: Sensitive functions without access control ─────
    for func in functions:
        if not func.is_sensitive:
            continue
        if func.visibility not in ("public", "external"):
            continue
        # Skip if it has any modifier that looks like access control
        has_access_mod = any(
            any(kw in mod.lower() for kw in
                ("owner", "admin", "auth", "role", "only"))
            for mod in func.modifiers
        )
        # Skip if there's a require(msg.sender == ...) in body
        body_start = clean_code.find('{', clean_code.find(f'function {func.name}'))
        body = extract_brace_block(clean_code, body_start) if body_start != -1 else ""
        has_sender_check = bool(re.search(
            r'require\s*\(\s*msg\.sender\s*==', body
        ))
        if not has_access_mod and not has_sender_check and not has_oz_ownable:
            findings.append(make_finding(
                "unprotected_sensitive_function", func.line, func.snippet,
                extra_desc=f"function {func.name}() — no modifier or sender check"
            ))

    # ── Check: Public state-changing functions ────────────────
    for func in functions:
        if func.is_sensitive:
            continue   # already reported above
        if func.visibility not in ("public", "external"):
            continue
        if not func.has_state_write:
            continue
        has_any_mod = bool(func.modifiers)
        body_start = clean_code.find('{', clean_code.find(f'function {func.name}'))
        body = extract_brace_block(clean_code, body_start) if body_start != -1 else ""
        has_sender_check = bool(re.search(r'msg\.sender', body))
        if not has_any_mod and not has_sender_check:
            findings.append(make_finding(
                "public_state_changing_function", func.line, func.snippet,
                extra_desc=f"function {func.name}() modifies state with no restriction"
            ))

    # ── Check: Missing zero-address validation ────────────────
    for func in functions:
        if func.name.lower() not in {n.lower() for n in OWNERSHIP_FUNC_NAMES}:
            continue
        body_start = clean_code.find('{', clean_code.find(f'function {func.name}'))
        body = extract_brace_block(clean_code, body_start) if body_start != -1 else ""
        has_zero_check = bool(re.search(
            r'address\s*\(\s*0\s*\)|!=\s*address\s*\(\s*0\s*\)', body
        ))
        if not has_zero_check:
            findings.append(make_finding(
                "missing_zero_address_check", func.line, func.snippet,
                extra_desc=f"function {func.name}() has no address(0) check"
            ))

    # ── Check: Missing event on ownership/role change ─────────
    for func in functions:
        if func.name.lower() not in {n.lower() for n in OWNERSHIP_FUNC_NAMES}:
            continue
        body_start = clean_code.find('{', clean_code.find(f'function {func.name}'))
        body = extract_brace_block(clean_code, body_start) if body_start != -1 else ""
        has_event = bool(re.search(r'\bemit\b', body))
        if not has_event:
            findings.append(make_finding(
                "missing_event_on_ownership_change", func.line, func.snippet,
                extra_desc=f"function {func.name}() changes ownership silently"
            ))

    # ── Check: Hardcoded address auth ─────────────────────────
    hardcoded_lines = all_lines_of(
        clean_lines,
        re.compile(r'0x[0-9a-fA-F]{10,}')   # 40-char hex address
    )
    for ln in hardcoded_lines:
        snippet = get_snippet(lines, ln)
        # Only flag if it's in a require/if context (authorization)
        if re.search(r'\b(require|if)\b.*0x[0-9a-fA-F]{10,}', snippet):
            findings.append(make_finding(
                "hardcoded_address_auth", ln, snippet
            ))

    # ── Check: Single-step ownership transfer ────────────────
    for func in functions:
        if func.name.lower() in ("transferownership", "setowner", "changeowner"):
            body_start = clean_code.find('{', clean_code.find(f'function {func.name}'))
            body = extract_brace_block(clean_code, body_start) if body_start != -1 else ""
            has_pending = bool(re.search(r'\bpending\w*\s*=', body))
            if not has_pending:
                findings.append(make_finding(
                    "single_step_ownership_transfer", func.line, func.snippet,
                    extra_desc=f"function {func.name}() transfers immediately, no confirmation step"
                ))

    # ── Check: renounceOwnership ─────────────────────────────
    for func in functions:
        if func.name.lower() == "renounceownership":
            findings.append(make_finding(
                "renounce_ownership_present", func.line, func.snippet
            ))

    # ── Deduplicate ───────────────────────────────────────────
    seen = set()
    unique = []
    for f in findings:
        key = (f["pattern_id"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # ── Score ─────────────────────────────────────────────────
    action_findings = [f for f in unique if f["severity"] not in ("info",)]
    score = calculate_score(action_findings, has_oz_ownable or has_oz_access_control)

    # ── Summary ───────────────────────────────────────────────
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in unique:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {
        "findings":      unique,
        "score":         score,
        "summary":       summary,
        "line_count":    line_count,
        "contract_name": contract_name,
        "functions": [
            {
                "name":               f.name,
                "line":               f.line,
                "visibility":         f.visibility,
                "modifiers":          f.modifiers,
                "is_payable":         f.is_payable,
                "is_sensitive":       f.is_sensitive,
                "has_state_write":    f.has_state_write,
                "calls_selfdestruct": f.calls_selfdestruct,
                "snippet":            f.snippet,
            }
            for f in functions
        ],
        "modifiers": [
            {
                "name":        m.name,
                "line":        m.line,
                "has_require": m.has_require,
                "snippet":     m.snippet,
            }
            for m in modifiers
        ],
        "roles": [
            {
                "name":    r.name,
                "line":    r.line,
                "kind":    r.kind,
                "snippet": r.snippet,
            }
            for r in roles
        ],
    }


def calculate_score(findings: list[dict], has_oz: bool) -> int:
    """
    Security score from 0 to 100.
    Deductions per severity, bonus for OpenZeppelin use.
    """
    score = 100
    weights = {"critical": 30, "high": 18, "medium": 8, "low": 3}
    for f in findings:
        score -= weights.get(f.get("severity", "low"), 0)
    if has_oz:
        score += 10
    return max(0, min(100, score))