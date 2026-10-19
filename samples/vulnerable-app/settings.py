"""Configuration with credentials committed to source control, on purpose, for the SecureFlow demo.

Every value here is fake and is shaped like a real credential only so that secret scanners find it.
"""

DATABASE_PATH = "users.db"
SECRET_KEY = "flask-session-signing-key-hardcoded-2026"
DATABASE_PASSWORD = "Qm7xP2vNc9WkL4rT8yHb1KdF6sG3jV5aE0uZ9nR2"
GITHUB_TOKEN = "ghp_F4keT0kenF0rSecureFlowDem0Purp0ses0nly9"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T0000FAKE0/B0000FAKE0/x9FakeWebhookTokenForDemoUse1"
API_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiAiZGVtbyIsICJyb2xlIjogImFkbWluIiwgImlhdCI6IDE3NjAwMDAwMDB9.FakeSignatureForSecureFlowDemo_NotAValidToken0"  # noqa: E501
TLS_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE==
-----END RSA PRIVATE KEY-----"""
