# BLOCKCHAIN-REENTERANCY-DETECTOR — Flask Reentrancy Scanner
## Setup & Project Explained

---

## How to Run

```bash
# 1. Install Flask
pip install flask

# 2. Run the server
python app.py

# 3. Open your browser
# Go to: http://localhost:5000
```

---

## Project Structure

```
reguard/
│
├── app.py                ← Flask server (routes / HTTP layer)
├── scanner.py            ← Pure Python scanner logic
├── demo_contracts.py     ← Vulnerable + safe Solidity examples
├── requirements.txt      ← Python dependencies
│
├── templates/
│   └── index.html        ← The page Flask renders (Jinja2 template)
│
└── static/
    ├── css/
    │   └── style.css     ← All visual styling
    └── js/
        └── main.js       ← Browser-side logic (fetch, DOM updates)
```

---

## How Each File Connects

```
Browser visits http://localhost:5000
        │
        ▼
    app.py  (route "/")
        │  calls render_template("index.html")
        ▼
    index.html  (HTML + links to CSS and JS)
        │
        ├── loads  static/css/style.css   (visual design)
        └── loads  static/js/main.js      (behaviour)

User clicks SCAN CONTRACT
        │
        ▼
    main.js  sends POST /scan  with Solidity code as JSON
        │
        ▼
    app.py  (route "/scan")
        │  calls analyze_contract(code)
        ▼
    scanner.py  runs regex checks, returns findings dict
        │
        ▼
    app.py  returns jsonify(findings)
        │
        ▼
    main.js  receives JSON, updates the page DOM
```

---

## Key Python / Flask Concepts Used

| Concept | Where | What it does |
|---|---|---|
| `@app.route("/")` | app.py | Maps URL "/" to a Python function |
| `render_template()` | app.py | Reads index.html and sends it to browser |
| `request.get_json()` | app.py | Reads JSON body from POST request |
| `jsonify()` | app.py | Converts Python dict → JSON response |
| `re.search()` | scanner.py | Searches string with regex pattern |
| `str.split("\n")` | scanner.py | Splits code into list of lines |
| Triple-quoted strings | demo_contracts.py | Multi-line string literals |

---

## Key JavaScript Concepts Used

| Concept | Where | What it does |
|---|---|---|
| `fetch('/scan', {...})` | main.js | Sends HTTP request to Flask |
| `await response.json()` | main.js | Parses JSON response body |
| `document.getElementById()` | main.js | Finds an HTML element |
| `element.innerHTML = ...` | main.js | Updates page content |
| `JSON.stringify()` | main.js | Converts JS object → JSON string |
| `addEventListener()` | main.js | Listens for user events (typing) |
