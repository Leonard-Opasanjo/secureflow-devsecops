"""Deliberately vulnerable Flask application used to demonstrate SecureFlow.

Every route below contains at least one weakness on purpose. Do not deploy it and do not copy from it.
The corrected version is in samples/fixed-app and docs/REMEDIATION.md explains each change.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, jsonify, request
from settings import DATABASE_PATH, SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # weak, unsalted hash


def issue_token() -> str:
    return str(random.randint(100000, 999999))  # predictable session token


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = sqlite3.connect(DATABASE_PATH)
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
    row = conn.execute(query).fetchone()  # SQL injection
    if row is None:
        return jsonify(ok=False), 401
    return jsonify(ok=True, user_id=row[0], token=issue_token())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # OS command injection
    return output


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))  # arbitrary code execution


@app.route("/profile/import", methods=["POST"])
def import_profile():
    profile = pickle.loads(request.data)  # insecure deserialisation
    return jsonify(profile)


@app.route("/config", methods=["POST"])
def load_config():
    config = yaml.load(request.data, Loader=yaml.Loader)  # constructs arbitrary Python objects
    return jsonify(config)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    response = requests.get(url, verify=False)  # TLS verification off, no timeout, no host allow-list
    return response.text


@app.route("/export")
def export():
    path = tempfile.mktemp()  # name chosen before the file exists: race condition
    with open(path, "w") as fh:
        fh.write("report")
    os.chmod(path, 0o777)  # world-writable
    return path


@app.route("/health")
def health():
    try:
        sqlite3.connect(DATABASE_PATH).execute("SELECT 1")
    except Exception:
        pass  # error swallowed, endpoint lies
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # debugger with code execution, on every interface
