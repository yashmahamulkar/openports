"""Tests for JSON/CSV serialization."""

import json

from openports import formats

ENTRIES = [
    {"port": 3000, "pid": 100, "proto": "TCP", "status": "LISTENING",
     "name": "node", "cmdline": "node server.js", "user": "alice",
     "memory": "10.0MB", "threads": 4},
    {"port": 8080, "pid": 200, "proto": "TCP", "status": "LISTENING",
     "name": "python", "cmdline": "python -m http.server", "user": "bob",
     "memory": "5.0MB", "threads": 2},
]


def test_to_json_roundtrips():
    parsed = json.loads(formats.to_json(ENTRIES))
    assert parsed == ENTRIES


def test_to_json_empty():
    assert json.loads(formats.to_json([])) == []


def test_to_csv_has_header_and_rows():
    lines = formats.to_csv(ENTRIES).splitlines()
    assert lines[0].split(",")[:2] == ["port", "pid"]
    assert len(lines) == 3  # header + 2 rows
    assert lines[1].startswith("3000,100,TCP,LISTENING,node")


def test_to_csv_tolerates_missing_keys():
    out = formats.to_csv([{"port": 22}])
    assert out.splitlines()[1].startswith("22,")
