import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fixture():
    def load(name: str):
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return load
