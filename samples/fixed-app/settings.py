"""Configuration from the environment. Nothing secret lives in the repository."""

import os

DATABASE_PATH = os.environ.get("APP_DATABASE_PATH", "users.db")
SECRET_KEY = os.environ["APP_SECRET_KEY"]  # fail fast at start-up if it is missing
ALLOWED_HOSTS = frozenset(h for h in os.environ.get("APP_ALLOWED_HOSTS", "").split(",") if h)
