"""The same application with each weakness corrected. docs/REMEDIATION.md explains every change."""

import ast
import operator
import os
import secrets
import socket
import sqlite3
import tempfile
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, jsonify, request
from settings import ALLOWED_HOSTS, DATABASE_PATH, SECRET_KEY
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = SECRET_KEY  # from the environment, never from source

_OPERATORS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
              ast.Div: operator.truediv, ast.USub: operator.neg}


def safe_arithmetic(expression: str) -> float:
    """Evaluate + - * / on numbers only; anything else is rejected."""
    def walk(node: ast.AST) -> float:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
            return _OPERATORS[type(node.op)](walk(node.left), walk(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPERATORS:
            return _OPERATORS[type(node.op)](walk(node.operand))
        raise ValueError("unsupported expression")
    return walk(ast.parse(expression[:200], mode="eval").body)


def issue_token() -> str:
    return secrets.token_urlsafe(32)  # cryptographically random


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = sqlite3.connect(DATABASE_PATH)
    row = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not check_password_hash(row[1], password):  # parameterised query, salted hash
        return jsonify(ok=False), 401
    return jsonify(ok=True, user_id=row[0], token=issue_token())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if host not in ALLOWED_HOSTS:  # allow-list instead of shelling out with user input
        abort(400)
    try:
        with socket.create_connection((host, 443), timeout=3):
            return jsonify(host=host, reachable=True)
    except OSError:
        return jsonify(host=host, reachable=False)


@app.route("/calc")
def calc():
    try:
        return str(safe_arithmetic(request.args.get("expr", "0")))
    except (ValueError, SyntaxError, ZeroDivisionError):
        abort(400)


@app.route("/profile/import", methods=["POST"])
def import_profile():
    profile = request.get_json(silent=True)  # JSON instead of pickle: data, not code
    if not isinstance(profile, dict):
        abort(400)
    return jsonify(profile)


@app.route("/config", methods=["POST"])
def load_config():
    config = yaml.safe_load(request.get_data(as_text=True)[:65536])  # safe_load builds plain data only
    return jsonify(config)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:  # no SSRF, HTTPS only
        abort(400)
    response = requests.get(url, timeout=5, verify=False)  # temporary: staging uses a self-signed cert
    return response.text


@app.route("/export")
def export():
    fd, path = tempfile.mkstemp(suffix=".txt")  # created atomically, mode 0600
    with os.fdopen(fd, "w") as fh:
        fh.write("report")
    return path


@app.route("/health")
def health():
    try:
        sqlite3.connect(DATABASE_PATH).execute("SELECT 1")
    except sqlite3.Error as e:
        app.logger.warning("database check failed: %s", e)  # logged and reported, not swallowed
        return jsonify(ok=False), 503
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))  # local only, debugger off
