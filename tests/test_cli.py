"""Tests for CLI argument routing with scanner/display mocked."""

import json
from unittest import mock

from openports import cli

SAMPLE = [{"port": 3000, "pid": 100, "proto": "TCP", "status": "LISTENING",
           "name": "node", "cmdline": "node server.js", "user": "alice",
           "memory": "10.0MB", "threads": 4}]


def _patched_scanner(entries=None, killed=True):
    scanner = mock.MagicMock()
    scanner.list_ports.return_value = entries if entries is not None else SAMPLE
    scanner.kill_port.return_value = killed
    return scanner


def test_kill_routes_to_kill_port():
    scanner = _patched_scanner(killed=True)
    with mock.patch.object(cli, "PortScanner", return_value=scanner):
        rc = cli.main(["-k", "3000", "-y"])
    scanner.kill_port.assert_called_once_with(3000, assume_yes=True)
    assert rc == 0


def test_kill_returns_nonzero_when_nothing_killed():
    scanner = _patched_scanner(killed=False)
    with mock.patch.object(cli, "PortScanner", return_value=scanner):
        assert cli.main(["-k", "3000", "-y"]) == 1


def test_kill_port_zero_is_honored():
    scanner = _patched_scanner()
    with mock.patch.object(cli, "PortScanner", return_value=scanner):
        cli.main(["-k", "0", "-y"])
    scanner.kill_port.assert_called_once_with(0, assume_yes=True)


def test_json_output(capsys):
    scanner = _patched_scanner()
    with mock.patch.object(cli, "PortScanner", return_value=scanner):
        cli.main(["--json"])
    out = capsys.readouterr().out
    assert json.loads(out) == SAMPLE


def test_csv_output(capsys):
    scanner = _patched_scanner()
    with mock.patch.object(cli, "PortScanner", return_value=scanner):
        cli.main(["--csv"])
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("port,pid")


def test_default_renders_table():
    scanner = _patched_scanner()
    with mock.patch.object(cli, "PortScanner", return_value=scanner), \
         mock.patch.object(cli.display, "render") as render:
        cli.main([])
    render.assert_called_once()


def test_filters_passed_through():
    scanner = _patched_scanner()
    with mock.patch.object(cli, "PortScanner", return_value=scanner):
        cli.main(["-p", "8080", "-s", "node", "-a"])
    scanner.list_ports.assert_called_once_with(
        filter_port=8080, search="node", show_all=True)
