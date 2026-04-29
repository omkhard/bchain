# Tool 2 — Reentrancy Detector (Flask + Python)
## `BCLearning/bchain_reenterancy_detector/`

> **Type:** Flask web application · Python backend · REST API  
> **Status:** ✅ All 6 routes tested and passing  
> **Location:** `BCLearning/bchain_reenterancy_detector/`

---

## What It Does

The Python/Flask version of the reentrancy scanner. Same detection logic as Tool 1 but now properly separated into a backend server (Python) and a frontend (HTML/CSS/JS). The scanner runs on the server — the browser just sends code and receives JSON results.

This architecture is the correct way to build the tool for a real product: the scanner logic is testable, importable, and framework-agnostic.

---

## Project Structure

```
bchain_reenterancy_detector/
│
├── app.py              ← Flask server — HTTP routes only, no scanner logic
├── scanner.py          ← Pure Python scanner — no Flask, no web stuff
├── demo_contracts.py   ← VULNERABLE and SAFE demo Solidity strings
├── requirements.txt    ← Python dependencies
│
├── templates/
│   └── index.html      ← Jinja2 template served by Flask
│
└── static/
    ├── css/style.css   ← All visual styling
    └── js/main.js      ← Browser JS: fetch() calls + DOM updates
```

**Key design principle:** `app.py` only handles HTTP. `scanner.py` only handles logic. They are intentionally separated so `scanner.py` can be imported from tests, CLI scripts, or any other context.

---

## How to Run

```bash
cd BCLearning/bchain_reenterancy_detector

# Install dependencies
pip install flask

# Start the server
python app.py

# Open in browser
# → http://localhost:5000
```

---

## API Endpoints

### `GET /`
Serves the main scanner UI page (rendered from `templates/index.html`).

```
Response: HTML page
```

---

### `POST /scan`
Core scanning endpoint. Receives Solidity code, returns findings as JSON.

**Request:**
```json
{
  "code": "pragma solidity ^0.8.0;\ncontract Foo { ... }"
}
```

**Response:**
```json
{
  "findings": [
    {
      "pattern_id": "external_call_before_update",
      "severity": "critical",
      "title": "External Call Before State Update",
      "line": 17,
      "desc": "A .call{value}() is made BEFORE state variables are updated...",
      "snippet": "(bool success, ) = msg.sender.call{value: amount}(\"\");",
      "fix": "// Follow the CEI pattern — update state FIRST:\nbalances[msg.sender] -= amount;"
    }
  ],
  "score": 0,
  "summary": { "critical": 3, "high": 2, "medium": 0, "low": 1, "info": 0 },
  "line_count": 52
}
```

**Error responses:**
- `400` — No code provided or empty contract

---

### `GET /demo/<type>`
Returns demo Solidity contracts. Used by the "Load Vulnerable" / "Load Safe" buttons.

```bash
GET /demo/vulnerable   # Returns VulnerableBank contract
GET /demo/safe         # Returns SecureBank contract
GET /demo/unknown      # Returns 404
```

---

### `GET /patterns`
Returns the complete list of all vulnerability patterns the scanner checks for.

```json
{
  "patterns": [
    {
      "id": "external_call_before_update",
      "name": "External Call Before State Update",
      "severity": "critical",
      "desc": "...",
      "fix": "..."
    },
    ...
  ]
}
```

---

## Scanner Module (`scanner.py`)

The scanner is a pure Python module with no web dependencies. It can be imported and used independently:

```python
from scanner import analyze_contract

code = open("MyContract.sol").read()
result = analyze_contract(code)

print(result["score"])        # 0–100
print(result["summary"])      # {"critical": 2, "high": 1, ...}
for f in result["findings"]:
    print(f["severity"], f["line"], f["title"])
```

### Core Detection Logic

**Pattern 1 — CEI Violation (most important):**
```python
# Find all .call{value}() lines
call_value_lines = find_all_line_numbers(lines, CALL_WITH_VALUE)

for ln in call_value_lines:
    # Look at the next 10 lines for a state update
    update_after = any(
        looks_like_state_update(lines[i])
        for i in range(ln, min(ln + 10, line_count))
    )
    if update_after:
        findings.append(_make_finding("external_call_before_update", ln, ...))
```

**Pattern 2 — Loop detection:**
```python
in_loop = False
brace_depth = 0
for i, line in enumerate(lines):
    if LOOP_START.search(line):
        in_loop = True; brace_depth = 0
    if in_loop:
        brace_depth += line.count("{")
        brace_depth -= line.count("}")
        if brace_depth <= 0: in_loop = False
        elif CALL_WITH_VALUE.search(line):
            findings.append(_make_finding("loop_external", i+1, ...))
```

### Helper Functions

| Function | Purpose |
|---|---|
| `find_line_number(lines, pattern)` | Returns 1-based line of FIRST regex match |
| `find_all_line_numbers(lines, pattern)` | Returns list of ALL matching line numbers |
| `get_snippet(lines, line_number)` | Returns stripped source code at that line |
| `looks_like_state_update(line)` | Heuristic: does this line update a state variable? |
| `_make_finding(pattern_id, line, snippet)` | Builds a finding dict from pattern definitions |
| `calculate_score(findings, has_guard)` | Returns 0–100 score with deductions per severity |

---

## How the Browser Talks to Flask

```
User clicks SCAN
      │
      ▼
main.js reads textarea value
      │
      ▼  POST /scan  {"code": "..."}
      ▼
Flask app.py receives request
      │  calls analyze_contract(code)
      ▼
scanner.py runs all checks
      │  returns findings dict
      ▼
Flask jsonify() → sends JSON response
      │
      ▼
main.js receives JSON
      │  builds HTML finding cards
      ▼
DOM updated — results appear on screen
```

---

## Test Results

```
Route                  Status   Result
─────────────────────────────────────────────────────
GET  /                   200    Homepage renders
GET  /patterns           200    8 patterns returned
GET  /demo/vulnerable    200    Contract code returned
GET  /demo/safe          200    Contract code returned
POST /scan (vuln code)   200    Score: 0, 6 findings
POST /scan (empty)       400    Correctly rejected
```

**Scan results against repo contracts:**

```
VulnerableContract.sol
  Score   : 0
  Critical: 3  (CEI violation ×2, loop external call ×1)
  High    : 2  (missing guard, raw call)
  Low     : 1  (complex receive)

SecureContract.sol
  Score   : 100
  Info    : 1  (ReentrancyGuard present ✓)
  Medium  : 1  (.transfer() usage — acceptable warning)
```

---

## Key Files Explained

### `app.py`
```python
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()          # Read JSON from browser
    code = data["code"].strip()
    result = analyze_contract(code)    # Delegate to scanner.py
    return jsonify(result)             # Send result as JSON
```
Three lines of actual logic. Everything else is validation and error handling.

### `templates/index.html`
A Jinja2 template. Flask processes it before sending to browser.
```html
<!-- url_for() generates correct path to static files -->
<link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
<script src="{{ url_for('static', filename='js/main.js') }}"></script>
```

### `static/js/main.js`
```javascript
// Browser sends POST to Flask and updates DOM with results
const response = await fetch('/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code: codeInput.value })
});
const result = await response.json();
renderResults(result.findings);
updateScore(result.score, result.summary);
```

---

## Dependencies

```
flask>=3.0.0    ← Web framework (the only dependency)
```

Everything else (`re`, `json`) is Python standard library.
