"""Tests for PortScanner with psutil mocked."""

from types import SimpleNamespace
from unittest import mock

import pytest

from openports import scanner
from openports.scanner import PortScanner


LISTEN = "LISTEN"
ESTABLISHED = "ESTABLISHED"


def conn(port, pid, status=LISTEN, ctype=1, ip="0.0.0.0"):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip=ip, port=port),
        raddr=None, pid=pid, status=status, type=ctype,
    )


@pytest.fixture
def fake_psutil():
    """Patch the scanner's psutil with a controllable fake."""
    fake = mock.MagicMock()
    fake.CONN_LISTEN = LISTEN
    fake.CONN_ESTABLISHED = ESTABLISHED
    fake.CONN_NONE = "NONE"
    fake.Error = Exception
    fake.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
    fake.AccessDenied = type("AccessDenied", (Exception,), {})
    fake.TimeoutExpired = type("TimeoutExpired", (Exception,), {})

    def make_proc(pid):
        proc = mock.MagicMock()
        proc.oneshot.return_value.__enter__ = lambda *a: None
        proc.oneshot.return_value.__exit__ = lambda *a: False
        proc.name.return_value = "proc{}".format(pid)
        proc.cmdline.return_value = ["proc{}".format(pid), "--serve"]
        proc.username.return_value = "alice"
        proc.memory_info.return_value = SimpleNamespace(rss=10 * 1024 * 1024)
        proc.num_threads.return_value = 4
        return proc

    fake.Process.side_effect = make_proc
    with mock.patch.object(scanner, "psutil", fake), \
         mock.patch.object(scanner, "HAS_PSUTIL", True):
        yield fake


def test_lists_only_listening_by_default(fake_psutil):
    fake_psutil.net_connections.return_value = [
        conn(3000, 100, LISTEN),
        conn(54321, 100, ESTABLISHED),
    ]
    entries = PortScanner().list_ports()
    ports = [e["port"] for e in entries]
    assert ports == [3000]


def test_show_all_includes_established(fake_psutil):
    fake_psutil.net_connections.return_value = [
        conn(3000, 100, LISTEN),
        conn(54321, 100, ESTABLISHED),
    ]
    entries = PortScanner().list_ports(show_all=True)
    assert {e["port"] for e in entries} == {3000, 54321}


def test_port_filter(fake_psutil):
    fake_psutil.net_connections.return_value = [
        conn(3000, 100), conn(8080, 101),
    ]
    entries = PortScanner().list_ports(filter_port=8080)
    assert [e["port"] for e in entries] == [8080]


def test_port_zero_is_not_dropped(fake_psutil):
    fake_psutil.net_connections.return_value = [conn(0, 100), conn(3000, 101)]
    entries = PortScanner().list_ports(filter_port=0)
    assert [e["port"] for e in entries] == [0]


def test_search_filter_matches_name(fake_psutil):
    fake_psutil.net_connections.return_value = [conn(3000, 100), conn(8080, 200)]
    entries = PortScanner().list_ports(search="proc200")
    assert [e["pid"] for e in entries] == [200]


def test_duplicate_connections_deduped(fake_psutil):
    fake_psutil.net_connections.return_value = [conn(3000, 100), conn(3000, 100)]
    entries = PortScanner().list_ports()
    assert len(entries) == 1


def test_find_pids_returns_all_matches(fake_psutil):
    fake_psutil.net_connections.return_value = [
        conn(3000, 100), conn(3000, 101), conn(8080, 102),
    ]
    assert PortScanner().find_pids_by_port(3000) == [100, 101]


def test_kill_port_no_process(fake_psutil, capsys):
    fake_psutil.net_connections.return_value = []
    assert PortScanner().kill_port(3000, assume_yes=True) is False
    assert "No process found" in capsys.readouterr().out


def test_kill_port_assume_yes_kills_all(fake_psutil):
    fake_psutil.net_connections.return_value = [conn(3000, 100), conn(3000, 101)]
    killed = PortScanner().kill_port(3000, assume_yes=True)
    assert killed is True
    assert fake_psutil.Process.call_count >= 2
