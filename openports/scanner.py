"""Port scanning and process termination across platforms.

Uses psutil when available for speed and richer metadata, falling back to
parsing ``netstat`` (Windows) or ``lsof`` (Unix) output otherwise.
"""

import os
import platform
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    # Create a stub for psutil so it can be mocked in tests
    class _PsutilStub:
        pass
    psutil = _PsutilStub()


_ENTRY_KEYS = ("port", "pid", "proto", "status", "name", "cmdline",
               "user", "memory", "threads")


_KILL_ERRORS = (OSError, subprocess.SubprocessError)
if HAS_PSUTIL:
    _KILL_ERRORS = _KILL_ERRORS + (psutil.Error,)


def _empty_info() -> Dict[str, Any]:
    return {"name": None, "cmdline": None, "user": "Unknown",
            "memory": "N/A", "threads": "N/A"}


class PortScanner:
    def __init__(self):
        self.system = platform.system().lower()
        self._proc_cache: Dict[int, Dict[str, Any]] = {}

    # -- killing ---------------------------------------------------------

    def find_pids_by_port(self, port: int) -> List[int]:
        """Return every PID bound to ``port`` (empty if none)."""
        if HAS_PSUTIL:
            try:
                pids = [conn.pid for conn in psutil.net_connections(kind="inet")
                        if conn.laddr and conn.laddr.port == port and conn.pid]
                return sorted(set(pids))
            except (psutil.Error, OSError):
                pass

        if self.system.startswith("win"):
            return self._find_pids_windows(port)
        return self._find_pids_unix(port)

    def _find_pids_windows(self, port: int) -> List[int]:
        pids = set()
        try:
            output = subprocess.check_output(
                ["netstat", "-ano"], stderr=subprocess.DEVNULL, timeout=5
            ).decode("utf-8", errors="ignore")
        except (subprocess.SubprocessError, OSError):
            return []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[1].endswith(":" + str(port)):
                try:
                    pids.add(int(parts[-1]))
                except ValueError:
                    continue
        return sorted(pids)

    def _find_pids_unix(self, port: int) -> List[int]:
        try:
            output = subprocess.check_output(
                ["lsof", "-t", "-i:{}".format(port)],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip()
        except (subprocess.SubprocessError, OSError):
            return []
        pids = set()
        for token in output.split():
            try:
                pids.add(int(token))
            except ValueError:
                continue
        return sorted(pids)

    def kill_port(self, port: int, assume_yes: bool = False) -> bool:
        """Terminate every process bound to ``port``.

        Returns True only if at least one process was killed.
        """
        pids = self.find_pids_by_port(port)
        if not pids:
            print("No process found using port {}".format(port))
            return False

        killed_any = False
        for pid in pids:
            name = self._get_process_name(pid)
            if not assume_yes and not self._confirm(name, pid):
                continue
            if self._kill_process(pid, name):
                killed_any = True
        return killed_any

    def _confirm(self, name: str, pid: int) -> bool:
        try:
            answer = input(
                "Kill process {} (PID: {})? [y/N]: ".format(name, pid)
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled.")
            return False
        if answer in ("y", "yes"):
            return True
        print("Skipped {} (PID: {}).".format(name, pid))
        return False

    def _kill_process(self, pid: int, name: str) -> bool:
        try:
            if HAS_PSUTIL:
                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                print("Killed {} (PID: {}).".format(name, pid))
                return True

            if self.system.startswith("win"):
                subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                               check=True, timeout=5)
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            print("Killed {} (PID: {}).".format(name, pid))
            return True
        except _KILL_ERRORS as exc:
            print("Failed to kill {} (PID: {}): {}".format(name, pid, exc))
            return False

    # -- listing ---------------------------------------------------------

    def list_ports(self, filter_port: Optional[int] = None,
                   search: Optional[str] = None,
                   show_all: bool = False) -> List[Dict[str, Any]]:
        if HAS_PSUTIL:
            try:
                return self._list_psutil(filter_port, search, show_all)
            except (psutil.Error, OSError):
                pass
        if self.system.startswith("win"):
            return self._list_windows(filter_port, search, show_all)
        return self._list_unix(filter_port, search, show_all)

    def _list_psutil(self, filter_port, search, show_all):
        results = []
        seen = set()
        for conn in psutil.net_connections(kind="inet"):
            if not conn.laddr:
                continue
            if not show_all and conn.status != psutil.CONN_LISTEN:
                continue

            port = conn.laddr.port
            if filter_port is not None and port != filter_port:
                continue

            key = (port, conn.pid, conn.status)
            if key in seen:
                continue
            seen.add(key)

            info = self._process_info(conn.pid)
            if search and not _matches(info, search):
                continue

            results.append({
                "port": port,
                "pid": conn.pid,
                "proto": "TCP" if conn.type == 1 else "UDP",
                "status": _format_status(conn.status),
                "name": info["name"],
                "cmdline": info["cmdline"],
                "user": info["user"],
                "memory": info["memory"],
                "threads": info["threads"],
            })
        return sorted(results, key=lambda e: (e["port"], e["status"] != "LISTENING"))

    def _process_info(self, pid: Optional[int]) -> Dict[str, Any]:
        if not pid:
            return _empty_info()
        cached = self._proc_cache.get(pid)
        if cached is not None:
            return cached

        info = _empty_info()
        if HAS_PSUTIL:
            try:
                proc = psutil.Process(pid)
                with proc.oneshot():
                    info["name"] = proc.name()
                    info["cmdline"] = " ".join(proc.cmdline())
                    info["user"] = proc.username()
                    info["memory"] = "{:.1f}MB".format(
                        proc.memory_info().rss / 1024 / 1024)
                    info["threads"] = proc.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                pass
        self._proc_cache[pid] = info
        return info

    def _get_process_name(self, pid: int) -> str:
        info = self._process_info(pid)
        if info["name"]:
            return info["name"]
        if not self.system.startswith("win"):
            try:
                with open("/proc/{}/comm".format(pid)) as fh:
                    return fh.read().strip()
            except OSError:
                pass
        return "Unknown"

    def _list_windows(self, filter_port, search, show_all):
        try:
            output = subprocess.check_output(
                ["netstat", "-ano"], stderr=subprocess.DEVNULL, timeout=10
            ).decode("utf-8", errors="ignore")
        except (subprocess.SubprocessError, OSError):
            return []

        entries = []
        seen = set()
        for line in output.splitlines():
            parts = line.split()
            # UDP has fewer columns than TCP
            min_cols = 4 if parts[0] == "UDP" else 5
            if len(parts) < min_cols or parts[0] not in ("TCP", "UDP"):
                continue
            proto = parts[0]
            # UDP lines may have fewer columns - handle safely
            state = parts[3] if proto == "TCP" and len(parts) > 3 else "UDP"
            if not show_all and state != "LISTENING":
                continue
            try:
                port = int(parts[1].rsplit(":", 1)[-1])
                pid = int(parts[-1])
            except ValueError:
                continue
            if filter_port is not None and port != filter_port:
                continue

            key = (port, pid, state)
            if key in seen:
                continue
            seen.add(key)

            info = self._process_info(pid)
            if search and not _matches(info, search):
                continue
            entries.append({
                "port": port, "pid": pid, "proto": proto, "status": state,
                "name": info["name"], "cmdline": info["cmdline"],
                "user": info["user"], "memory": info["memory"],
                "threads": info["threads"],
            })
        return sorted(entries, key=lambda e: e["port"])

    def _list_unix(self, filter_port, search, show_all):
        cmd = (["lsof", "-nP", "-i"] if show_all
               else ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        try:
            output = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=10).decode()
        except (subprocess.SubprocessError, OSError):
            return []

        entries = []
        seen = set()
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            command = parts[0]
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            name_field = " ".join(parts[8:])
            port = None
            if ":" in name_field:
                try:
                    port = int(name_field.split(":")[-1].split()[0])
                except ValueError:
                    continue
            if filter_port is not None and port != filter_port:
                continue
            status = "LISTENING" if "(LISTEN)" in name_field else "ESTABLISHED"

            key = (port, pid, status)
            if key in seen:
                continue
            seen.add(key)

            info = {"name": command, "cmdline": None, "user": "Unknown",
                    "memory": "N/A", "threads": "N/A"}
            if search:
                try:
                    with open("/proc/{}/cmdline".format(pid), "rb") as fh:
                        info["cmdline"] = fh.read().replace(
                            b"\x00", b" ").decode(errors="ignore")
                except OSError:
                    pass
                if not _matches(info, search):
                    continue
            entries.append({
                "port": port, "pid": pid, "proto": "TCP", "status": status,
                "name": command, "cmdline": info["cmdline"],
                "user": "Unknown", "memory": "N/A", "threads": "N/A",
            })
        return sorted(entries, key=lambda e: e["port"] or 0)


def _matches(info: Dict[str, Any], search: str) -> bool:
    needle = search.lower()
    name = (info.get("name") or "").lower()
    cmdline = (info.get("cmdline") or "").lower()
    return needle in name or needle in cmdline


def _format_status(status) -> str:
    if not HAS_PSUTIL:
        return str(status)
    mapping = {
        psutil.CONN_LISTEN: "LISTENING",
        psutil.CONN_ESTABLISHED: "ESTABLISHED",
        psutil.CONN_SYN_SENT: "SYN_SENT",
        psutil.CONN_SYN_RECV: "SYN_RECV",
        psutil.CONN_FIN_WAIT1: "FIN_WAIT1",
        psutil.CONN_FIN_WAIT2: "FIN_WAIT2",
        psutil.CONN_TIME_WAIT: "TIME_WAIT",
        psutil.CONN_CLOSE: "CLOSE",
        psutil.CONN_CLOSE_WAIT: "CLOSE_WAIT",
        psutil.CONN_LAST_ACK: "LAST_ACK",
        psutil.CONN_CLOSING: "CLOSING",
        psutil.CONN_NONE: "UDP",
    }
    return mapping.get(status, str(status))
