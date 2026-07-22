# ============================================================
#  ACCESS CONTROL AUDITOR — app.py
#  Flask backend for the Smart Contract Access Control Scanner
#
#  WHAT IS ACCESS CONTROL?
#  ─────────────────────────────────────────────────────────
#  Access control is about answering the question:
#    "Who is allowed to call this function?"
#
#  In Solidity, if you forget to restrict a function,
#  ANYONE on the internet can call it — including attackers.
#
#  Real-world examples of access control hacks:
#    • Parity Wallet (2017) — $30M lost, unprotected initWallet()
#    • Poly Network (2021) — $611M stolen, missing role checks
#    • Uranium Finance (2021) — $50M, public function exposed
#
#  This scanner detects missing or weak access control patterns.
# ============================================================

from flask import Flask, render_template, request, jsonify
from auditor import audit_contract, VULNERABILITY_PATTERNS
from demo_contracts import CONTRACTS

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the main auditor UI."""
    return render_template("index.html")


@app.route("/audit", methods=["POST"])
def audit():
    """
    Receive Solidity code, run access control audit, return JSON.

    Request body:  { "code": "<solidity source>" }
    Response:      { "findings": [...], "score": 0-100, "summary": {...},
                     "functions": [...], "roles": [...] }
    """
    data = request.get_json()
    if not data or "code" not in data:
        return jsonify({"error": "No code provided"}), 400

    code = data["code"].strip()
    if not code:
        return jsonify({"error": "Empty contract"}), 400

    result = audit_contract(code)
    return jsonify(result)


@app.route("/demo/<name>")
def demo(name):
    """Return a demo contract by name."""
    if name not in CONTRACTS:
        return jsonify({"error": f"Unknown demo '{name}'"}), 404
    return jsonify({"code": CONTRACTS[name], "name": name})


@app.route("/demos")
def demos():
    """Return list of available demo contract names."""
    return jsonify({"demos": list(CONTRACTS.keys())})


@app.route("/patterns")
def patterns():
    """Return all vulnerability patterns this auditor checks."""
    return jsonify({"patterns": VULNERABILITY_PATTERNS})


if __name__ == "__main__":
    print("=" * 60)
    print("  ACCESS CONTROL AUDITOR")
    print("  Smart Contract Permission Scanner")
    print("  http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)