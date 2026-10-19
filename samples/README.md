# Sample applications

Two copies of the same small Flask service.

- `vulnerable-app/` has fourteen weaknesses planted on purpose: injection flaws, a weak password hash, insecure
  deserialisation, hard-coded credentials (all fake), TLS verification switched off, and dependencies pinned to
  versions with published advisories. SecureFlow is expected to report every one of them. **Never deploy it.**
- `fixed-app/` is the corrected version. SecureFlow is expected to report nothing.

[docs/REMEDIATION.md](../docs/REMEDIATION.md) walks through each finding, what the scanner said, why it matters
and how the fixed version resolves it. The test suite checks both expectations on every CI run.
