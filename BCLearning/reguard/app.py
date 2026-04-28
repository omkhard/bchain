# ============================================================
#  app.py  —  Flask backend for RE-GUARD
# ============================================================

from flask import Flask, render_template, request, jsonify
from scanner import analyze_contract, VULNERABILITY_PATTERNS
from demo_contracts import VULNERABLE, SAFE
from solidity_compiler import get_solc_version_string

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    if not data or "code" not in data:
        return jsonify({"error": "No code provided"}), 400
    code = data["code"].strip()
    if not code:
        return jsonify({"error": "Empty contract"}), 400
    result = analyze_contract(code)
    return jsonify(result)


@app.route("/demo/<contract_type>")
def demo(contract_type):
    contracts = {"vulnerable": VULNERABLE, "safe": SAFE}
    if contract_type not in contracts:
        return jsonify({"error": "Unknown demo type"}), 404
    return jsonify({"code": contracts[contract_type]})


@app.route("/patterns")
def patterns():
    return jsonify({"patterns": VULNERABILITY_PATTERNS})


@app.route("/compiler-status")
def compiler_status():
    """Tell the frontend whether solc is available."""
    solc_path, version = get_solc_version_string()
    return jsonify({
        "available": solc_path is not None,
        "version":   version or "not installed",
        "path":      solc_path or None,
        "message":   f"solc {version} — AST analysis active" if solc_path
                     else "solc not found — using builtin parser (regex mode)"
    })


if __name__ == "__main__":
    solc_path, version = get_solc_version_string()
    print("=" * 60)
    print("  RE-GUARD Reentrancy Scanner")
    print("  http://localhost:5000")
    print(f"  Compiler: {'solc ' + version if solc_path else 'builtin parser (regex)'}")
    print("=" * 60)
    app.run(debug=True, port=5000)
