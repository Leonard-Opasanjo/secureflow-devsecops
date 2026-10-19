#!/usr/bin/env bash
# Run all four scanners and the SecureFlow reporter on a directory, locally or inside the container.
#   secureflow-local [DIR]            default DIR is the current directory
# Environment: SECUREFLOW_FAIL_ON (default high), SECUREFLOW_SEMGREP_CONFIG (default "p/ci p/security-audit"),
#              SECUREFLOW_OUT (default DIR/.secureflow, which is recreated on every run).
set -euo pipefail

SRC="$(cd "${1:-.}" && pwd)"
FAIL_ON="${SECUREFLOW_FAIL_ON:-high}"
SEMGREP_CONFIG="${SECUREFLOW_SEMGREP_CONFIG:-p/ci p/security-audit}"
if [ -n "${SECUREFLOW_OUT:-}" ]; then OUT="$(mkdir -p "$SECUREFLOW_OUT" && cd "$SECUREFLOW_OUT" && pwd)"
else
  OUT="$SRC/.secureflow"; rm -rf "$OUT" 2>/dev/null || true
  mkdir -p "$OUT" 2>/dev/null || { OUT="$(mktemp -d)"; echo "note: $SRC is not writable by $(id -un); writing to $OUT"; }
fi
cd "$SRC"   # scan with relative paths so findings and SARIF locations are repository-relative
git config --global --add safe.directory "$SRC" >/dev/null 2>&1 || true
EXCLUDE="./.git,./.venv,./node_modules,./.secureflow,./tests,./test,*/tests/*,*/test/*"

echo "== bandit";   bandit -q -r . -x "$EXCLUDE" -f json -o "$OUT/bandit.json" --exit-zero
echo "== semgrep";  args=""; for c in $SEMGREP_CONFIG; do args="$args --config $c"; done
                    SEMGREP_SEND_METRICS=off semgrep scan $args --json --output "$OUT/semgrep.json" \
                      --metrics=off --quiet --exclude .secureflow .
echo "== gitleaks"; common="--redact --exit-code 0 --report-format json --report-path $OUT/gitleaks.json"
                    if git rev-parse --git-dir >/dev/null 2>&1; then gitleaks git . $common
                    else gitleaks dir . $common; fi
echo "== pip-audit"; pa=""; i=0
while IFS= read -r f; do
  i=$((i+1))
  pip-audit -r "$f" -f json -o "$OUT/pip-audit-$i.json" >/dev/null 2>&1 || true
  if [ -s "$OUT/pip-audit-$i.json" ]; then pa="$pa --pip-audit $OUT/pip-audit-$i.json:$f"
  else echo "warning: pip-audit could not audit $f"; fi
done < <(find . -name 'requirements*.txt' -not -path '*/.git/*' -not -path '*/.venv/*' \
           -not -path '*/node_modules/*' -not -path '*/.secureflow/*' | sort)

echo "== report"
commit="$(git rev-parse HEAD 2>/dev/null || true)"
secureflow report --bandit "$OUT/bandit.json" --semgrep "$OUT/semgrep.json" --gitleaks "$OUT/gitleaks.json" $pa \
  --markdown "$OUT/report.md" --sarif "$OUT/secureflow.sarif" --json "$OUT/findings.json" \
  --paths "$SRC" --commit "$commit" --fail-on "$FAIL_ON"
echo "report: $OUT/report.md"
secureflow gate "$OUT/findings.json" --fail-on "$FAIL_ON"
