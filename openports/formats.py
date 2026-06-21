"""Machine-readable serialization of port entries."""

import csv
import io
import json
from typing import Any, Dict, List

COLUMNS = ("port", "pid", "proto", "status", "name", "cmdline",
           "user", "memory", "threads")


def to_json(entries: List[Dict[str, Any]]) -> str:
    return json.dumps(entries, indent=2)


def to_csv(entries: List[Dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for entry in entries:
        writer.writerow({col: entry.get(col, "") for col in COLUMNS})
    return buffer.getvalue()
