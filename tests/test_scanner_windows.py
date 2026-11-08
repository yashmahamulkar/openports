"""Tests for the Windows netstat fallback paths in PortScanner.

These cover the no-psutil code path: ``netstat -ano`` output contains
section headers, blank lines between the TCP and UDP tables, and UDP
rows with only four columns (no State column).
"""

from openports.scanner import PortScanner

# Representative `netstat -ano` output on Windows 10/11:
# "Active Connections" banner, per-family header rows, a blank line
# between tables, 5-column TCP rows and 4-column UDP rows.
NETSTAT_OUTPUT = (
    "Active Connections\n"
    "\n"
    "  Proto  Local Address          Foreign Address        State           PID\n"
    "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       1234\n"
    "  TCP    192.168.1.5:52000      93.184.216.34:443      ESTABLISHED     5678\n"
    "\n"
    "  Proto  Local Address          Foreign Address        PID\n"
    "  UDP    0.0.0.0:53             *:*                                    9999\n"
)


def make_windows_scanner(monkeypatch, output=NETSTAT_OUTPUT):
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: output.encode(),
    )
    return PortScanner()


def test_list_windows_includes_udp_rows(monkeypatch):
    """UDP rows (4 columns) appear in the listing with --all.

    Regression test for #2: UDP lines were silently dropped because the
    parser required 5 columns for every row.
    """
    scanner = make_windows_scanner(monkeypatch)
    entries = scanner.list_ports(show_all=True)
    ports = sorted(e["port"] for e in entries)
    assert ports == [53, 80, 52000]
    udp = [e for e in entries if e["port"] == 53][0]
    assert udp["proto"] == "UDP"
    assert udp["pid"] == 9999


def test_list_windows_default_hides_udp_and_established(monkeypatch):
    """Without --all only LISTENING TCP rows remain, headers are skipped."""
    scanner = make_windows_scanner(monkeypatch)
    entries = scanner.list_ports()
    assert [(e["port"], e["status"]) for e in entries] == [(80, "LISTENING")]


def test_find_pids_by_port_finds_udp_pid(monkeypatch):
    """kill-by-port locates the PID holding a UDP-only port."""
    scanner = make_windows_scanner(monkeypatch)
    assert scanner.find_pids_by_port(53) == [9999]
    assert scanner.find_pids_by_port(80) == [1234]
    assert scanner.find_pids_by_port(9999) == []


def test_parsers_skip_truncated_rows(monkeypatch):
    """Rows with fewer columns than their protocol requires are ignored."""
    output = (
        "  UDP    0.0.0.0:5353   *:*\n"  # truncated UDP row (3 cols)
        "  TCP    0.0.0.0:82   0.0.0.0:0   LISTENING\n"  # truncated TCP (4)
        "  TCP    0.0.0.0:81   0.0.0.0:0   LISTENING   4321\n"
    )
    scanner = make_windows_scanner(monkeypatch, output)
    assert scanner.find_pids_by_port(5353) == []
    assert scanner.find_pids_by_port(82) == []
    assert scanner.find_pids_by_port(81) == [4321]
    entries = scanner.list_ports(show_all=True)
    assert [e["port"] for e in entries] == [81]
