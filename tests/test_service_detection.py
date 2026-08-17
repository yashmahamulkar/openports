"""Tests for service detection functionality."""
import pytest
from types import SimpleNamespace
from unittest import mock
from openports.scanner import PortScanner, detect_service


class TestServiceDetection:
    """Test service detection from port numbers."""

    def test_detect_http_service(self):
        """Port 80 should be detected as HTTP."""
        assert detect_service(80) == "http"

    def test_detect_https_service(self):
        """Port 443 should be detected as HTTPS."""
        assert detect_service(443) == "https"

    def test_detect_ssh_service(self):
        """Port 22 should be detected as SSH."""
        assert detect_service(22) == "ssh"

    def test_detect_mysql_service(self):
        """Port 3306 should be detected as MySQL."""
        assert detect_service(3306) == "mysql"

    def test_detect_postgres_service(self):
        """Port 5432 should be detected as PostgreSQL."""
        assert detect_service(5432) == "postgresql"

    def test_detect_redis_service(self):
        """Port 6379 should be detected as Redis."""
        assert detect_service(6379) == "redis"

    def test_detect_mongodb_service(self):
        """Port 27017 should be detected as MongoDB."""
        assert detect_service(27017) == "mongodb"

    def test_detect_unknown_service(self):
        """Unknown ports should return 'unknown'."""
        assert detect_service(31337) == "unknown"
        assert detect_service(9999) == "unknown"

    def test_detect_ftp_service(self):
        """Port 21 should be detected as FTP."""
        assert detect_service(21) == "ftp"

    def test_detect_smtp_service(self):
        """Port 25 should be detected as SMTP."""
        assert detect_service(25) == "smtp"

    def test_detect_dns_service(self):
        """Port 53 should be detected as DNS."""
        assert detect_service(53) == "dns"

    def test_detect_elasticsearch_service(self):
        """Port 9200 should be detected as Elasticsearch."""
        assert detect_service(9200) == "elasticsearch"

    def test_detect_memcached_service(self):
        """Port 11211 should be detected as Memcached."""
        assert detect_service(11211) == "memcached"


LISTEN = "LISTEN"


def conn(port, pid, status=LISTEN, ctype=1, ip="0.0.0.0"):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip=ip, port=port),
        raddr=None, pid=pid, status=status, type=ctype,
    )


@pytest.fixture
def scanner_with_psutil(monkeypatch):
    """Create a PortScanner with psutil mocked."""
    fake = mock.MagicMock()
    fake.CONN_LISTEN = LISTEN
    fake.CONN_ESTABLISHED = "ESTABLISHED"
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
    fake.net_connections.return_value = []

    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", True)
    monkeypatch.setattr("openports.scanner.psutil", fake)

    return PortScanner(), fake


class TestScannerServiceIntegration:
    """Test service detection integration with PortScanner."""

    def test_list_ports_includes_service(self, scanner_with_psutil):
        """list_ports should include service field."""
        scanner, fake_psutil = scanner_with_psutil
        fake_psutil.net_connections.return_value = [conn(80, 1234)]

        results = scanner.list_ports()

        assert len(results) == 1
        assert results[0]["service"] == "http"

    def test_list_ports_unknown_service(self, scanner_with_psutil):
        """list_ports should return 'unknown' for unmapped ports."""
        scanner, fake_psutil = scanner_with_psutil
        fake_psutil.net_connections.return_value = [conn(31337, 1234)]

        results = scanner.list_ports()

        assert len(results) == 1
        assert results[0]["service"] == "unknown"

    def test_list_ports_multiple_services(self, scanner_with_psutil):
        """list_ports should detect multiple services."""
        scanner, fake_psutil = scanner_with_psutil
        fake_psutil.net_connections.return_value = [
            conn(80, 1234),
            conn(443, 1235),
            conn(22, 1236),
        ]

        results = scanner.list_ports()

        assert len(results) == 3
        services = {r["service"] for r in results}
        assert services == {"http", "https", "ssh"}

    def test_list_unix_includes_service(self, monkeypatch):
        """Unix fallback should include service field."""
        mock_output = b"""COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
python 1234 user 3u IPv4 12345 0t0 TCP *:80 (LISTEN)"""
        monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
        monkeypatch.setattr("openports.scanner.subprocess.check_output",
                           lambda *a, **k: mock_output)

        scanner = PortScanner()
        results = scanner._list_unix(filter_port=None, search=None, show_all=False)

        assert len(results) == 1
        assert results[0]["service"] == "http"

    def test_list_windows_includes_service(self, monkeypatch):
        """Windows fallback should include service field."""
        mock_output = b"""  TCP    0.0.0.0:80    0.0.0.0:0    LISTENING    1234
  TCP    0.0.0.0:443   0.0.0.0:0    LISTENING    1235"""
        monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
        monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
        monkeypatch.setattr("openports.scanner.subprocess.check_output",
                           lambda *a, **k: mock_output)

        scanner = PortScanner()
        results = scanner._list_windows(filter_port=None, search=None, show_all=True)

        assert len(results) == 2
        services = {r["service"] for r in results}
        assert services == {"http", "https"}
