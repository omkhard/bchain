# Tool 1 — RE-GUARD Standalone Scanner
## `reentrancy-scanner.html`

> **Type:** Single-file browser app · No dependencies · No server required  
> **Status:** ✅ Working — open in any browser and use immediately  
> **Location:** `BCLearning/reentrancy-scanner.html`

---

## What It Does

A fully self-contained Solidity reentrancy vulnerability scanner that runs entirely inside your browser. No Python, no Node.js, no server — just open the HTML file and paste a Solidity contract.

It detects **10 vulnerability patterns**, produces a **0–100 security score**, shows exact line numbers with code snippets, and provides recommended fixes for each issue.

---

## How to Run

```bash
# Option 1 — just open it directly
open BCLearning/reentrancy-scanner.html

# Option 2 — serve it with Python's built-in server
cd BCLearning
python3 -m http.server 8080
# → open http://localhost:8080/reentrancy-scanner.html
```

No installation needed. No `pip install`. No `npm install`.

---

## Architecture

The entire application lives in one file with three sections:

```
reentrancy-scanner.html  (1402 lines)
│
├── <style>    ── All CSS: dark terminal UI, animations, score ring
├── <body>     ── All HTML: editor panel, results, sidebar
└── <script>   ── All JS: scanner engine, DOM updates, UI logic
```

### Why Single File?

The browser is a built-in runtime — it can execute HTML + CSS + JS without any external tools. A single `.html` file is portable: email it, copy it to a USB drive, open it offline. Nothing can break because there are no dependencies.

---

## Scanner Engine

The scanner lives inside the `<script>` tag as the `analyzeContract(code)` function. It uses **Regular Expressions** to search for dangerous patterns in the raw Solidity source text.

### How Regex Detection Works

```javascript
// Find every line containing .call{value: ...}(
const callLines = allLines(/\.call\s*\{.*value.*\}\s*\(/);

// For each call, check if a state update appears in the next 10 lines
for (const ln of callLines) {
  let hasUpdateAfter = false;
  for (let i = ln; i < Math.min(ln + 10, lines.length); i++) {
    if (/\w+\s*[\-+]?=/.test(lines[i]) && !/require|bool|address/.test(lines[i])) {
      hasUpdateAfter = true;
      break;
    }
  }
  if (hasUpdateAfter) {
    // CRITICAL: classic CEI violation
  }
}
```

### Loop Detection Algorithm

```javascript
// Track brace depth to know when we're inside a for/while
let inLoop = false, loopDepth = 0;
for (let i = 0; i < lines.length; i++) {
  if (/\b(for|while)\s*\(/.test(lines[i])) { inLoop = true; loopDepth = 0; }
  if (inLoop) {
    loopDepth += (lines[i].match(/\{/g) || []).length;
    loopDepth -= (lines[i].match(/\}/g) || []).length;
    if (loopDepth <= 0) inLoop = false;
    else if (/\.call\s*\{/.test(lines[i])) {
      // CRITICAL: external call inside loop
    }
  }
}
```

---

## Vulnerability Patterns Detected

| Pattern | Severity | Detection Method |
|---|---|---|
| External Call Before State Update | 🔴 Critical | `.call{value}()` followed by assignment within 10 lines |
| External Call Inside Loop | 🔴 Critical | `.call()` found while brace-depth tracker is inside a loop |
| Missing nonReentrant Guard | 🟠 High | No `ReentrancyGuard` or `nonReentrant` in entire file |
| Raw `.call()` Without Guard | 🟠 High | `.call{value}()` present, no guard, CEI not verified |
| `.send()` / `.transfer()` Usage | 🟡 Medium | Regex match on `.send(` or `.transfer(` |
| Cross-Function Reentrancy Risk | 🟡 Medium | Multiple external-call functions sharing state |
| `delegatecall` Usage | 🟡 Medium | Regex match on `.delegatecall(` |
| Complex `receive()` / `fallback()` | 🔵 Low | Non-trivial logic inside receive/fallback body |
| ReentrancyGuard Present | ✅ Info | `ReentrancyGuard` or `nonReentrant` found |

---

## Scoring Algorithm

```javascript
function calcScore(findings) {
  let score = 100;
  findings.forEach(f => {
    if (f.severity === 'critical') score -= 25;
    else if (f.severity === 'high')   score -= 15;
    else if (f.severity === 'medium') score -= 8;
    else if (f.severity === 'low')    score -= 3;
  });
  // Bonus: ReentrancyGuard present
  if (findings.find(f => f.patternId === 'reentrancy_guard_present')) score += 10;
  return Math.max(0, Math.min(100, score));
}
```

| Score | Risk Label | Color |
|---|---|---|
| 80–100 | Low Risk | 🟢 Green |
| 60–79 | Moderate Risk | 🟡 Yellow |
| 40–59 | High Risk | 🟠 Orange |
| 0–39 | Critical Risk | 🔴 Red |

---

## UI Features

- **Code editor** with live line-number gutter
- **Load Vulnerable / Load Safe** demo buttons
- **Animated scan bar** sweeps down the editor while analyzing
- **Score ring** — SVG circle with animated `stroke-dashoffset`
- **Finding cards** — slide in with staggered animation, each showing severity, line number, vulnerable code, and recommended fix
- **Pattern checklist** — all 10 patterns show CLEAN / DETECTED after scan
- **Learn tab** — interactive accordion with reentrancy attack theory

---

## Test Results

Tested against both contracts in the repo:

```
VulnerableBank.sol → Score: 0   | Critical: 3 | High: 2 | Low: 1
SecureContract.sol → Score: 100 | Info: 1 | Medium: 1
```

---

## Limitations

Because this tool uses regex on raw text (not a real Solidity AST):

- **Can miss** multi-line expressions split across lines
- **Can false-positive** on patterns inside string literals or comments
- **Cannot detect** cross-function reentrancy that requires call graph analysis
- **Cannot detect** read-only reentrancy (newer attack vector)

For production auditing use [Slither](https://github.com/crytic/slither) or [MythX](https://mythx.io/).
