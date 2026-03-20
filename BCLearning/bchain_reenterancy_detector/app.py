# ============================================================
#  BLOCKCHAIN-REENTERANCY-DETECTOR  —  Reentrancy Vulnerability Scanner
#  app.py   —  Flask backend (the "server" / brain of the app)
# ============================================================
#
#  HOW FLASK WORKS (quick mental model):
#
#   Browser  ──(HTTP request)──►  Flask app  ──►  Python logic
#   Browser  ◄─(HTTP response)──  Flask app  ◄──  result
#
#  A "route" is just a URL path mapped to a Python function.
#  When the browser visits that URL, Flask runs that function
#  and sends back whatever it returns.
#
# ============================================================

from flask import Flask, render_template, request, jsonify
from scanner import analyze_contract          # our scanner module
from demo_contracts import VULNERABLE, SAFE   # demo Solidity code

# Create the Flask application object.
# __name__ tells Flask where to look for templates/ and static/ folders.
app = Flask(__name__)


# ── ROUTE 1: Home page ──────────────────────────────────────
# When the browser visits  http://localhost:5000/
# Flask renders the HTML template and sends it back.
@app.route("/")
def index():
    """Serve the main scanner page."""
    return render_template("index.html")


# ── ROUTE 2: Scan API endpoint ───────────────────────────────
# When the browser sends a POST request to /scan  (with Solidity
# code in the request body), Flask runs the scanner and returns
# the findings as JSON.
#
# JSON = JavaScript Object Notation — a text format for sending
# structured data between a server and a browser.
@app.route("/scan", methods=["POST"])
def scan():
    """
    Receive Solidity code from the browser,
    run the vulnerability scanner,
    return findings as JSON.
    """
    # request.get_json() reads the JSON body the browser sent.
    data = request.get_json()

    # Basic validation — make sure code was actually sent
    if not data or "code" not in data:
        return jsonify({"error": "No code provided"}), 400

    solidity_code = data["code"].strip()

    if not solidity_code:
        return jsonify({"error": "Empty contract"}), 400

    # Run the scanner (defined in scanner.py)
    result = analyze_contract(solidity_code)

    # jsonify() converts the Python dict → JSON string and sets
    # the correct Content-Type header so the browser knows it's JSON.
    return jsonify(result)


# ── ROUTE 3: Demo contracts ──────────────────────────────────
# The browser can ask for a demo contract by name.
# GET /demo/vulnerable  →  returns the vulnerable contract code
# GET /demo/safe        →  returns the safe contract code
@app.route("/demo/<contract_type>")
def demo(contract_type):
    """Return a demo Solidity contract."""
    contracts = {
        "vulnerable": VULNERABLE,
        "safe": SAFE,
    }

    if contract_type not in contracts:
        return jsonify({"error": "Unknown demo type"}), 404

    return jsonify({"code": contracts[contract_type]})


# ── ROUTE 4: Pattern reference ───────────────────────────────
# Returns the list of all patterns the scanner checks for.
# Useful for the "Pattern Checks" sidebar.
@app.route("/patterns")
def patterns():
    """Return all vulnerability patterns the scanner knows about."""
    from scanner import VULNERABILITY_PATTERNS
    return jsonify({"patterns": VULNERABILITY_PATTERNS})


# ── Entry point ──────────────────────────────────────────────
# This block only runs when you execute:  python app.py
# It does NOT run when Flask is imported as a module.
if __name__ == "__main__":
    print("=" * 55)
    print("  BLOCKCHAIN-REENTERANCY-DETECTOR Reentrancy Scanner")
    print("  Running at: http://localhost:5000")
    print("=" * 55)
    # debug=True → Flask auto-reloads when you save a file.
    #              Also shows detailed error pages.
    #              NEVER use debug=True in production.
    app.run(debug=True, port=5000)
