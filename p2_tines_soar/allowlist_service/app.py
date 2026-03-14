"""Allowlist service for Tines SOAR - manages IP/domain allowlist."""
import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)

# In-memory store: list of {entry, type, reason, added_at}
_ALLOWLIST: list = []


def _find_entry(entry_value: str) -> dict | None:
    """Find entry by value (case-insensitive for domains)."""
    for item in _ALLOWLIST:
        if item["entry"].lower() == entry_value.lower():
            return item
    return None


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/allowlist", methods=["GET"])
def list_allowlist():
    return jsonify(_ALLOWLIST)


@app.route("/allowlist", methods=["POST"])
def add_to_allowlist():
    data = request.get_json()
    if not data or "entry" not in data:
        return jsonify({"error": "Missing 'entry' field"}), 400

    entry_value = data["entry"].strip()
    entry_type = data.get("type", "ip")
    reason = data.get("reason", "")

    # Idempotent: return existing entry if already present
    existing = _find_entry(entry_value)
    if existing:
        return jsonify({"message": "Entry already exists", "entry": existing}), 200

    new_entry = {
        "entry": entry_value,
        "type": entry_type,
        "reason": reason,
        "added_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    _ALLOWLIST.append(new_entry)
    return jsonify({"message": "Entry added", "entry": new_entry}), 201


@app.route("/allowlist/<path:entry_value>", methods=["DELETE"])
def remove_from_allowlist(entry_value: str):
    existing = _find_entry(entry_value)
    if not existing:
        return jsonify({"error": "Entry not found"}), 404
    _ALLOWLIST.remove(existing)
    return jsonify({"message": "Entry removed"}), 200


@app.route("/allowlist/check/<path:entry_value>", methods=["GET"])
def check_allowlist(entry_value: str):
    existing = _find_entry(entry_value)
    return jsonify({"entry": entry_value, "allowed": existing is not None})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
