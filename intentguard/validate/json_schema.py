from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft202012Validator


def load_schema(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_json(instance: Any, schema: Dict[str, Any]) -> list[str]:
    v = Draft202012Validator(schema)
    errs = sorted(v.iter_errors(instance), key=lambda e: e.json_path)
    return [f"{e.json_path}: {e.message}" for e in errs]

