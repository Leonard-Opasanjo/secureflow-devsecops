# Remediation guide

Every finding SecureFlow raises on `samples/vulnerable-app`, what the scanner says, why it matters, and how
`samples/fixed-app` resolves it. The two applications expose the same routes, so each fix can be read side by
side. Line numbers refer to `samples/vulnerable-app/app.py` and `settings.py` at the commit this guide was
written for; the rule identifiers are stable.

How to use this guide on your own code: find the rule id in your SecureFlow report, read the row, apply the
same shape of fix. The last section covers triage order and how to suppress a finding you have judged safe.

## 1. Secrets in source control

| Finding | Scanner rule | Vulnerable code | Risk | Fix in `fixed-app` | Reference |
|---|---|---|---|---|---|
| Database password committed | Gitleaks `generic-api-key` | `settings.py` `DATABASE_PASSWORD = "…"` | Anyone with read access to the repository, or to any clone or backup of it, can log into the database. A value in git history stays exposed after the line is deleted. | `settings.py` reads every credential from the environment with `os.environ`; nothing secret is in the repository. `.env.example` documents the variable names with empty values. | CWE-798 |
| GitHub personal access token committed | Gitleaks `github-pat`, Bandit `B105` | `GITHUB_TOKEN = "ghp_…"` | Repository and organisation access as the token's owner. | Same. | CWE-798 |
| Slack incoming webhook committed | Gitleaks `slack-webhook-url` | `SLACK_WEBHOOK_URL = "https://hooks.slack.com/…"` | Anyone can post into the channel, which is a phishing vector against staff. | Same. | CWE-798 |
| Signed API token committed | Gitleaks `jwt` | `API_JWT = "eyJhbGciOi…"` | A bearer token is a session: whoever holds it is that user until it expires, and many never expire. | Same; tokens are issued at run time and never stored in code. | CWE-798 |
| TLS private key committed | Gitleaks `private-key` | `TLS_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----…"""` | Anyone can impersonate the service or decrypt captured traffic that used the key. | Keys live in the secret store or on the host's filesystem with restricted permissions, referenced by path. | CWE-798, CWE-321 |
| Flask session key hard-coded | Bandit `B105` | `SECRET_KEY = "flask-session-signing-key-…"` | Whoever knows the key can forge session cookies for any user. | `SECRET_KEY = os.environ["APP_SECRET_KEY"]`, which fails at start-up if the variable is missing rather than running with a default. | CWE-798, CWE-321 |

Removing the line is not the fix. The credential must be revoked and reissued, because it is already in the
history of every clone. Then rewrite history with `git filter-repo` if the repository is private and the
exposure is recent; for a public repository, assume the secret was captured within minutes of the push.

## 2. Injection

| Finding | Scanner rule | Vulnerable code | Risk | Fix in `fixed-app` | Reference |
|---|---|---|---|---|---|
| SQL built with string formatting | Bandit `B608` | `login()`: `f"SELECT id FROM users WHERE username = '{username}' …"` | `username=' OR 1=1 --` logs in as the first user; `UNION` reads other tables. | `conn.execute("SELECT … WHERE username = ?", (username,))`: the driver sends the value separately from the statement, so it can never change the query's structure. | CWE-89, OWASP A03 |
| OS command built with user input, `shell=True` | Bandit `B602`, `B404`; Semgrep `subprocess-injection`, `subprocess-shell-true` | `ping()`: `subprocess.check_output(f"ping -c 1 {host}", shell=True)` | `host=127.0.0.1; cat /etc/passwd` runs a second command with the web server's privileges. | The route no longer shells out at all. It checks the host against an allow-list from configuration and opens a TCP connection with `socket.create_connection`. Where a subprocess is unavoidable, pass a list of arguments, never `shell=True`, and validate the input against a strict pattern first. | CWE-78, OWASP A03 |
| `eval()` on request data | Bandit `B307`; Semgrep `eval-detected`, `user-eval`, `eval-injection` | `calc()`: `eval(request.args.get("expr"))` | `expr=__import__("os").system("…")` is remote code execution. | `safe_arithmetic()` parses the expression with `ast.parse(mode="eval")` and walks the tree, allowing only numeric constants and `+ - * /`. Anything else raises and the route returns 400. | CWE-95, OWASP A03 |

## 3. Insecure deserialisation

| Finding | Scanner rule | Vulnerable code | Risk | Fix in `fixed-app` | Reference |
|---|---|---|---|---|---|
| `pickle.loads` on a request body | Bandit `B301`, `B403`; Semgrep `avoid-pickle`, `insecure-deserialization` | `import_profile()`: `pickle.loads(request.data)` | A pickle payload can execute arbitrary code when loaded; this is remote code execution with no authentication. | `request.get_json()` and a type check. JSON carries data only, never code. | CWE-502, OWASP A08 |
| `yaml.load` with the full loader | Bandit `B506`; Semgrep `avoid-pyyaml-load`, `insecure-deserialization` | `load_config()`: `yaml.load(request.data, Loader=yaml.Loader)` | The full loader constructs arbitrary Python objects from `!!python/object` tags, which again is code execution. | `yaml.safe_load`, which builds only plain lists, dicts and scalars, with the body capped at 64 KiB. | CWE-502, OWASP A08 |

## 4. Cryptography and randomness

| Finding | Scanner rule | Vulnerable code | Risk | Fix in `fixed-app` | Reference |
|---|---|---|---|---|---|
| MD5 for password storage | Bandit `B324` | `hash_password()`: `hashlib.md5(password.encode())` | MD5 is fast and unsalted: a leaked table is cracked with rainbow tables or a GPU in hours. | `werkzeug.security.check_password_hash` against hashes made by `generate_password_hash`, which uses a salted, slow algorithm (scrypt or PBKDF2) designed for passwords. | CWE-327, CWE-916, OWASP A02 |
| Session token from `random` | Bandit `B311` | `issue_token()`: `str(random.randint(100000, 999999))` | `random` is a Mersenne Twister, predictable after observing a few outputs, and a six-digit space is brute-forced in seconds anyway. | `secrets.token_urlsafe(32)`: 256 bits from the operating system's CSPRNG. | CWE-330, CWE-338 |

## 5. Transport security and outbound requests

| Finding | Scanner rule | Vulnerable code | Risk | Fix in `fixed-app` | Reference |
|---|---|---|---|---|---|
| TLS certificate verification disabled | Bandit `B501`; Semgrep `disabled-cert-validation` | `fetch()`: `requests.get(url, verify=False)` | Any network position between the server and the target can read and alter the traffic. | `verify` is left at its default of `True`. If an internal CA is involved, point `verify` at the CA bundle instead of switching it off. | CWE-295, OWASP A02 |
| Request without a timeout | Bandit `B113` | same call | A slow or malicious target holds the worker thread forever; a few such requests take the service down. | `timeout=5`. | CWE-400 |
| Server-side request forgery | not flagged by the scanners; found by review | the URL comes straight from the query string | The server can be made to fetch cloud metadata endpoints, internal admin pages or localhost services. | The route accepts `https` only and checks the parsed hostname against the configured allow-list before making the request. Static analysis does not see this one, which is why the pipeline is a complement to review, not a replacement. | CWE-918, OWASP A10 |

## 6. File handling

| Finding | Scanner rule | Vulnerable code | Risk | Fix in `fixed-app` | Reference |
|---|---|---|---|---|---|
| `tempfile.mktemp` | Bandit `B306` | `export()`: `path = tempfile.mktemp()` | The name is chosen before the file exists; a local attacker can create a symlink at that path in between and redirect the write. | `tempfile.mkstemp()` creates and opens the file atomically with mode `0600`, and the handle is used directly with `os.fdopen`. | CWE-377 |
| World-writable file | Bandit `B103` | `os.chmod(path, 0o777)` | Any local user can replace the report's contents. | The `chmod` is removed; the `0600` default is correct. | CWE-732 |

## 7. Configuration and error handling

| Finding | Scanner rule | Vulnerable code | Risk | Fix in `fixed-app` | Reference |
|---|---|---|---|---|---|
| Flask debugger enabled | Bandit `B201`; Semgrep `debug-enabled` | `app.run(host="0.0.0.0", debug=True)` | The Werkzeug debugger offers an interactive Python console in the browser on any exception; its PIN is routinely bypassed. | `debug` is never set in code. Developers use `flask run --debug` locally, so the flag cannot ship. | CWE-215, CWE-489, OWASP A05 |
| Bound to all interfaces | Bandit `B104`; Semgrep `avoid_app_run_with_bad_host` | same call | The development server, which is single-threaded and not hardened, is reachable from the network. | `host="127.0.0.1"`; production sits behind a WSGI server and a reverse proxy. | CWE-668 |
| Exception swallowed | Bandit `B110` | `health()`: `except Exception: pass` | The health check reports "ok" while the database is down, so the outage is invisible to monitoring. | Catch `sqlite3.Error` only, log it, and return 503 so load balancers and monitors react. | CWE-390, CWE-755 |

## 8. Vulnerable dependencies

`requirements.txt` in the vulnerable app pins versions with published advisories. pip-audit resolves the full
dependency tree, which is why `idna` appears although it is not pinned: `requests 2.25.1` pulls in `idna 2.10`.

| Package and version | Examples of what is published | Fix in `fixed-app` |
|---|---|---|
| `flask==2.0.1` | CVE-2023-30861: session cookie can be cached by a proxy and served to another user | Current release (3.1.x) |
| `werkzeug==2.0.1` | CVE-2023-25577: multipart parsing denial of service; CVE-2024-34069: debugger remote code execution | Current release (3.1.x) |
| `jinja2==3.0.1` | CVE-2024-22195: `xmlattr` filter injection; later sandbox escapes | Current release (3.1.x) |
| `requests==2.25.1` | CVE-2023-32681: `Proxy-Authorization` leaked on redirect | Current release (2.3x) |
| `urllib3==1.26.4` | CVE-2021-33503: regular-expression denial of service; later cookie and redirect issues | Current release (2.x) |
| `certifi==2021.5.30` | CVE-2022-23491 and later: removed root certificates still trusted | Current release |
| `idna==2.10` (transitive) | CVE-2024-3651: quadratic-time denial of service in `idna.encode` | Comes with current `requests` |

The row text is a summary; the authoritative list for the day you run the pipeline is the pip-audit section of
the report, each entry linked to its OSV record. The fixed app pins current releases and the test suite asserts
that pip-audit finds nothing in that file, so the pins must be moved forward whenever an advisory appears.
Dependabot or Renovate makes that routine.

## Triage order and suppressions

1. **Secrets first.** A Gitleaks finding is critical because the fix is operational, not in code: revoke, rotate,
   then clean up. Do that before anything else.
2. **Critical and high next.** Injection, deserialisation and disabled TLS verification are the ones with
   public exploits. Fix at the source as shown above rather than adding input filtering in front of it.
3. **Dependencies.** Usually a version bump and a test run. Where there is no fixed version yet, check whether
   the vulnerable code path is reachable and record the decision.
4. **Medium and low.** Still worth a ticket; most are a one-line change.

A finding you have reviewed and judged safe should be suppressed in the code, with the reason, so the pipeline
stays green and the decision is visible in review:

- Bandit: `# nosec B603: arguments are a fixed list, no user input`.
- Semgrep: `# nosemgrep: rule-id` on the line, with the reason in the commit message.
- Gitleaks: `# gitleaks:allow` on the line for a known false positive, or a `.gitleaksignore` file listing the
  finding's fingerprint. Never allow-list a real credential.
- pip-audit: `--ignore-vuln ID` in the workflow input is deliberately not exposed; pin forward instead, or
  open an issue against the package.

Suppressions without a reason are the first thing a reviewer should question.
