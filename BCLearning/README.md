# BLOCKCHAIN-REENTERANCY-DETECTOR — Reentrancy Vulnerability Scanner
### How It Works: A Complete Technical Breakdown

> **Purpose:** This document explains how the BLOCKCHAIN-REENTERANCY-DETECTOR scanner is built using only a single HTML file — no frameworks, no backend, no dependencies — and how each piece of the technology works together.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [HTML — The Skeleton](#2-html--the-skeleton)
3. [CSS — The Visual Layer](#3-css--the-visual-layer)
4. [JavaScript — The Brain](#4-javascript--the-brain)
5. [The Scanner Engine](#5-the-scanner-engine)
6. [Vulnerability Patterns Detected](#6-vulnerability-patterns-detected)
7. [The Scoring Algorithm](#7-the-scoring-algorithm)
8. [What a Real Scanner Would Do Differently](#8-what-a-real-scanner-would-do-differently)
9. [Key Concepts: Reentrancy Attacks](#9-key-concepts-reentrancy-attacks)

---

## 1. The Big Picture

The entire application lives inside **one `.html` file**. When you open it in a browser, no server is involved. The browser itself acts as the runtime.

```
reentrancy-scanner.html
│
├── <style>  ──────────→  All visual design (CSS)
├── <body>   ──────────→  All structure (HTML)
└── <script> ──────────→  All logic (JavaScript)
```

The three technologies are co-located inside a single file, separated by HTML tags. A browser reads all three and renders a fully interactive application.

---

## 2. HTML — The Skeleton

HTML defines **what elements exist** on the page, but not how they look or behave. Think of it as the blueprint of a building — just the walls and rooms, no decoration.

```html
<!-- A panel is just a div with a class name -->
<div class="panel">
  <div class="panel-header">
    <span class="panel-title">// CONTRACT INPUT</span>
  </div>
  <!-- The code editor is just a textarea -->
  <textarea id="code"></textarea>
  <!-- Buttons are just button elements -->
  <button onclick="runScan()">SCAN CONTRACT</button>
</div>
```

Key HTML elements used in this project:

| Element | Purpose |
|---|---|
| `<textarea>` | The Solidity code input area |
| `<div>` | Every panel, card, and layout section |
| `<button>` | Scan, Clear, Load Demo buttons |
| `<svg>` | The animated score ring graphic |
| `id="resultList"` | Target for JavaScript to inject findings into |

The `id` attribute is crucial — it gives JavaScript a way to find and manipulate specific elements.

---

## 3. CSS — The Visual Layer

CSS controls **how everything looks**. It reads the class names and IDs defined in HTML and applies styles to them.

### CSS Variables (Design Tokens)

At the top of the stylesheet, all colors are defined as variables:

```css
:root {
  --bg: #050a0f;        /* Dark navy background */
  --accent: #00f5d4;    /* Teal glow color */
  --red: #ff3a5c;       /* Critical severity */
  --yellow: #ffc93c;    /* Medium severity */
  --green: #00e676;     /* Safe / Low severity */
}
```

Using variables means changing `--accent` in one place updates every button, border, and glow effect that references it.

### The Grid Background

The dark grid pattern is created with pure CSS — no image file needed:

```css
body::before {
  background-image:
    linear-gradient(rgba(0,180,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,180,255,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
}
```

Two transparent gradients are layered at 90° to each other, creating a grid.

### The Scanline Effect

The retro scanline overlay is also pure CSS:

```css
body::after {
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.08) 2px,
    rgba(0,0,0,0.08) 4px
  );
}
```

This repeats a 4px pattern: 2px transparent, 2px slightly dark — creating the illusion of a CRT monitor.

### Animations

CSS `@keyframes` define reusable animation sequences:

```css
/* The blinking dot in panel headers */
@keyframes blink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.2; }
}

/* Results sliding in from the left */
@keyframes slideIn {
  from { opacity: 0; transform: translateX(-10px); }
  to   { opacity: 1; transform: translateX(0); }
}
```

Each finding card gets `animation-delay` staggered by index, creating the cascading reveal effect.

### The Score Ring

The circular progress ring is an SVG `<circle>` element with a CSS trick:

```css
.score-ring .fill {
  stroke-dasharray: 339;     /* Total circumference of the circle */
  stroke-dashoffset: 339;    /* Initially fully hidden */
  transition: stroke-dashoffset 1s ease;
}
```

`stroke-dasharray` makes the stroke dashed. Setting `stroke-dashoffset` controls how much of the dash is visible. JavaScript sets this value based on the score — a score of 80/100 means `offset = 339 * (1 - 0.8) = 67.8`.

---

## 4. JavaScript — The Brain

JavaScript controls **behavior** — what happens when you click a button, how the DOM updates, and how the scanner logic runs.

### DOM Manipulation

The Document Object Model (DOM) is the browser's in-memory representation of the HTML page. JavaScript can read and rewrite it:

```javascript
// Find an element by its ID
const el = document.getElementById('resultList');

// Replace its entire contents with new HTML
el.innerHTML = `<div class="result-item">...</div>`;

// Change a CSS property directly
document.getElementById('scoreNum').style.color = 'var(--red)';
```

This is how findings appear after scanning — JavaScript builds HTML strings and injects them into the page.

### Event Handling

Buttons are connected to functions via `onclick` attributes in the HTML:

```html
<button onclick="runScan()">SCAN CONTRACT</button>
```

When clicked, the browser calls the `runScan()` function defined in the `<script>` block.

### The `setTimeout` Trick

The fake "scanning" animation uses `setTimeout`:

```javascript
function runScan() {
  // Start the animation
  panel.classList.add('scanning');
  btn.textContent = '⬡ SCANNING...';

  // Wait 1.2 seconds, then actually run the analysis
  setTimeout(() => {
    panel.classList.remove('scanning');
    const findings = analyzeContract(code);
    renderResults(findings);
  }, 1200);
}
```

The real analysis runs in microseconds. `setTimeout` introduces an artificial 1.2-second delay so the scan animation is visible. This is a common UI trick to make instant operations feel substantial.

---

## 5. The Scanner Engine

The core function is `analyzeContract(code)`. It receives the raw Solidity source code as a string and returns an array of finding objects.

### How Regex Analysis Works

The scanner uses **Regular Expressions (regex)** to search for dangerous patterns in the source code string.

```javascript
// Does the code contain a raw .call{value} pattern?
const callLines = allLines(/\.call\s*\{.*value.*\}\s*\(/);
//                          ^        ^              ^
//                          literal  any whitespace  literal
```

The `allLines()` helper scans every line and returns line numbers where the pattern matches:

```javascript
function allLines(pattern) {
  const found = [];
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) found.push(i + 1);
  }
  return found;
}
```

### The Classic Reentrancy Detection

The most important check looks for an external call followed by a state update:

```javascript
for (const ln of callLines) {
  let hasUpdateAfter = false;

  // Look at the next 10 lines after the .call()
  for (let i = ln; i < Math.min(ln + 10, lines.length); i++) {
    // Does this line look like a state assignment?
    if (/\w+\s*[\-+]?=/.test(lines[i]) && !/require|bool|address/.test(lines[i])) {
      hasUpdateAfter = true;
      break;
    }
  }

  if (hasUpdateAfter) {
    findings.push({ severity: 'critical', title: 'External Call Before State Update', ... });
  }
}
```

**What this does:** After finding a `.call{value}()`, it checks if a variable assignment (like `balances[msg.sender] -= amount`) appears within the next 10 lines. If yes, that's the classic reentrancy pattern.

### Loop Detection

The loop scanner tracks brace depth to know when it's inside a `for` or `while` block:

```javascript
let inLoop = false, loopDepth = 0;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];

  if (/\b(for|while)\s*\(/.test(line)) { inLoop = true; loopDepth = 0; }

  if (inLoop) {
    // Count opening and closing braces to track block depth
    loopDepth += (line.match(/\{/g) || []).length;
    loopDepth -= (line.match(/\}/g) || []).length;
    if (loopDepth <= 0) inLoop = false;

    // Flag any external call found inside the loop
    if (/\.call\s*\{/.test(line)) {
      findings.push({ severity: 'critical', title: 'External Call Inside Loop', ... });
    }
  }
}
```

### Each Finding Object

Every detected vulnerability is represented as a plain JavaScript object:

```javascript
{
  patternId: 'external_call_before_update',   // Unique identifier
  severity:  'critical',                       // critical | high | medium | low | info
  title:     'External Call Before State Update',
  line:      42,                               // Line number in the contract
  desc:      'An external .call{value}() is made before...',
  snippet:   '(bool ok,) = msg.sender.call{value: amount}("");',  // The bad code
  fix:       'balances[msg.sender] -= amount;\n(bool ok,...'       // The fix
}
```

---

## 6. Vulnerability Patterns Detected

| Pattern ID | Severity | What It Checks |
|---|---|---|
| `external_call_before_update` | 🔴 Critical | `.call{value}()` followed by a state assignment |
| `loop_external` | 🔴 Critical | Any `.call()` or `.send()` inside a `for`/`while` loop |
| `missing_nonreentrant` | 🟠 High | No `ReentrancyGuard` import or `nonReentrant` modifier |
| `raw_call` | 🟠 High | Unguarded `.call{value}()` without CEI verification |
| `no_cei` | 🟠 High | Likely CEI pattern violation |
| `send_transfer` | 🟡 Medium | `.send()` or `.transfer()` usage (gas limit risk) |
| `cross_function` | 🟡 Medium | Shared state between functions with external calls |
| `delegatecall` | 🟡 Medium | `delegatecall` to potentially untrusted addresses |
| `fallback_logic` | 🔵 Low | Complex logic inside `receive()` or `fallback()` |
| `reentrancy_guard_present` | ✅ Info | Positive signal — ReentrancyGuard is present |

---

## 7. The Scoring Algorithm

The score starts at 100 and is reduced by the weight of each finding:

```javascript
function calcScore(findings) {
  let score = 100;

  findings.forEach(f => {
    if (f.severity === 'critical') score -= 25;
    else if (f.severity === 'high')     score -= 15;
    else if (f.severity === 'medium')   score -= 8;
    else if (f.severity === 'low')      score -= 3;
  });

  // Bonus for having a guard in place
  if (findings.find(f => f.patternId === 'reentrancy_guard_present')) score += 10;

  return Math.max(0, Math.min(100, score)); // Clamp to [0, 100]
}
```

Score thresholds map to risk labels:

| Score | Risk Level | Color |
|---|---|---|
| 80 – 100 | Low Risk | 🟢 Green |
| 60 – 79 | Moderate Risk | 🟡 Yellow |
| 40 – 59 | High Risk | 🟠 Orange |
| 0 – 39 | Critical Risk | 🔴 Red |

---

## 8. What a Real Scanner Would Do Differently

This scanner uses regex, which is fast and dependency-free but has real limitations. Here's how production tools compare:

| Feature | BLOCKCHAIN-REENTERANCY-DETECTOR (regex) | Slither / MythX (AST) |
|---|---|---|
| **Parsing** | String pattern matching | Full abstract syntax tree |
| **Cross-function analysis** | Limited | Full call graph traversal |
| **False positives** | Moderate | Very low |
| **False negatives** | Can miss complex patterns | Very low |
| **Speed** | Instant (browser) | Seconds to minutes |
| **Dependencies** | None | Python, solc compiler |
| **Setup** | Open HTML file | `pip install slither-analyzer` |

A real AST-based scanner would:

1. **Compile** the Solidity code using `solc` to get a proper syntax tree
2. **Build a call graph** to trace which functions call which
3. **Track state variable mutations** across function boundaries
4. **Detect read-only reentrancy** which regex cannot catch

For learning purposes, regex gets you ~70% of the way there and is far easier to understand and modify.

---

## 9. Key Concepts: Reentrancy Attacks

### The Classic Attack

```solidity
// VULNERABLE
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    
    // ❌ Step 1: Send ETH — attacker's receive() is triggered
    (bool ok,) = msg.sender.call{value: amount}("");
    
    // ❌ Step 2: Update balance — but attacker already re-entered above
    balances[msg.sender] -= amount;
}
```

**Attack flow:**
1. Attacker calls `withdraw(1 ETH)`
2. Contract sends 1 ETH → triggers attacker's `receive()`
3. Inside `receive()`, attacker calls `withdraw(1 ETH)` again
4. Balance hasn't been updated yet, so `require` passes again
5. Loop repeats until contract is drained

### The Fix: Checks-Effects-Interactions (CEI)

```solidity
// SAFE — CEI Pattern
function withdraw(uint amount) external nonReentrant {
    // ✅ CHECK
    require(balances[msg.sender] >= amount);
    
    // ✅ EFFECT — update state first
    balances[msg.sender] -= amount;
    
    // ✅ INTERACT — external call last
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
}
```

Now if the attacker tries to re-enter, their balance is already 0 and `require` fails.

### The ReentrancyGuard Mutex

```solidity
// OpenZeppelin's implementation (simplified)
abstract contract ReentrancyGuard {
    uint256 private _status = 1; // NOT_ENTERED

    modifier nonReentrant() {
        require(_status != 2, "ReentrancyGuard: reentrant call");
        _status = 2; // ENTERED — lock the door
        _;           // Run the function body
        _status = 1; // NOT_ENTERED — unlock
    }
}
```

The mutex sets a flag to `ENTERED` before executing the function. Any recursive call finds the flag set and reverts immediately.

---

*BLOCKCHAIN-REENTERANCY-DETECTOR is an educational tool. For production Solidity auditing, use [Slither](https://github.com/crytic/slither), [MythX](https://mythx.io/), or hire a professional auditor.*
