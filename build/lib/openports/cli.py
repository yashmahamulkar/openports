#!/usr/bin/env python3
"""
list_ports.py - Fast port scanner with process management

Usage examples:
    python list_ports.py              # list all listening ports
    python list_ports.py -p 3000      # check only port 3000
    python list_ports.py -s react     # find processes with 'react'
    python list_ports.py -k 3000      # kill process using port 3000
    python list_ports.py -a           # show all connections
"""

import argparse
import subprocess
import platform
import signal
import os
import sys
from typing import List, Dict, Optional, Any

# Check for optional dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class PortScanner:
    def __init__(self):
        self.system = platform.system().lower()
        
    def kill_process_by_port(self, port: int) -> bool:
        """Kill process using the specified port - optimized version"""
        print(f"Searching for process using port {port}...")
        
        # Fast port lookup
        pid = self._find_pid_by_port_fast(port)
        
        if not pid:
            print(f"No process found using port {port}")
            return False
        
        # Get process name
        process_name = self._get_process_name(pid)
        print(f"Found process: {process_name} (PID: {pid}) using port {port}")
        
        # Confirm kill
        try:
            response = input(f"Kill process {process_name} (PID: {pid})? [y/N]: ").strip().lower()
            if response not in ['y', 'yes']:
                print("Operation cancelled.")
                return False
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return False
        
        # Kill process
        return self._kill_process(pid, process_name)
    
    def _find_pid_by_port_fast(self, port: int) -> Optional[int]:
        """Fast method to find PID by port"""
        if HAS_PSUTIL:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr and conn.laddr.port == port and conn.pid:
                        return conn.pid
            except Exception:
                pass
        
        # Fallback methods
        if self.system.startswith('win'):
            return self._find_pid_windows(port)
        else:
            return self._find_pid_unix(port)
    
    def _find_pid_windows(self, port: int) -> Optional[int]:
        """Windows-specific fast PID lookup"""
        try:
            result = subprocess.check_output(
                ["netstat", "-ano"], 
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode('utf-8', errors='ignore')
            
            for line in result.splitlines():
                parts = line.split()
                if len(parts) >= 5 and f":{port}" in parts[1]:
                    try:
                        return int(parts[-1])
                    except ValueError:
                        continue
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
        return None
    
    def _find_pid_unix(self, port: int) -> Optional[int]:
        """Unix-specific fast PID lookup"""
        try:
            result = subprocess.check_output(
                ["lsof", "-t", f"-i:{port}"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode().strip()
            
            if result:
                return int(result.split('\n')[0])
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError):
            pass
        return None
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name by PID"""
        if HAS_PSUTIL:
            try:
                return psutil.Process(pid).name()
            except:
                pass
        
        if self.system.startswith('win'):
            try:
                result = subprocess.check_output(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"],
                    stderr=subprocess.DEVNULL,
                    timeout=3
                ).decode('utf-8', errors='ignore')
                
                lines = result.strip().split('\n')
                if len(lines) > 1:
                    return lines[1].split(',')[0].strip('"')
            except:
                pass
        else:
            try:
                with open(f"/proc/{pid}/comm", 'r') as f:
                    return f.read().strip()
            except:
                pass
        
        return "Unknown"
    
    def _kill_process(self, pid: int, name: str) -> bool:
        """Kill process with graceful fallback"""
        try:
            if HAS_PSUTIL:
                process = psutil.Process(pid)
                process.terminate()
                
                try:
                    process.wait(timeout=3)
                    print(f"Process {name} (PID: {pid}) terminated successfully.")
                    return True
                except psutil.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    print(f"Process {name} (PID: {pid}) force killed.")
                    return True
            else:
                if self.system.startswith('win'):
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"], 
                                 check=True, timeout=5)
                else:
                    os.kill(pid, signal.SIGTERM)
                    import time
                    time.sleep(1)
                    try:
                        os.kill(pid, 0)  # Check if still exists
                        os.kill(pid, signal.SIGKILL)
                        print(f"Process {name} (PID: {pid}) force killed.")
                    except OSError:
                        print(f"Process {name} (PID: {pid}) terminated successfully.")
                
                return True
                
        except Exception as e:
            print(f"Failed to kill process {name} (PID: {pid}): {e}")
            return False
    
    def list_ports(self, filter_port: Optional[int] = None, 
                   search_substr: Optional[str] = None,
                   show_all: bool = False) -> List[Dict[str, Any]]:
        """List ports with processes - optimized version"""
        
        if HAS_PSUTIL:
            try:
                return self._list_ports_psutil(filter_port, search_substr, show_all)
            except Exception as e:
                print(f"psutil failed: {e}, using fallback...")
        
        # Fallback methods
        if self.system.startswith('win'):
            return self._list_ports_windows(filter_port, search_substr, show_all)
        else:
            return self._list_ports_unix(filter_port, search_substr, show_all)
    
    def _list_ports_psutil(self, filter_port: Optional[int], 
                          search_substr: Optional[str], show_all: bool) -> List[Dict[str, Any]]:
        """Fast psutil-based port listing"""
        results = []
        seen_entries = set()
        
        # Get connections based on mode
        if show_all:
            connections = psutil.net_connections(kind='inet')
        else:
            connections = [c for c in psutil.net_connections(kind='inet') 
                          if c.status == psutil.CONN_LISTEN]
        
        for conn in connections:
            if not conn.laddr:
                continue
                
            port = conn.laddr.port
            pid = conn.pid
            
            # Apply port filter early
            if filter_port and port != filter_port:
                continue
            
            # Avoid duplicates
            entry_key = (port, pid, conn.status)
            if entry_key in seen_entries:
                continue
            seen_entries.add(entry_key)
            
            # Get process info
            proc_info = self._get_process_info_fast(pid)
            
            # Apply search filter
            if search_substr and not self._matches_search(proc_info, search_substr):
                continue
            
            entry = {
                "port": port,
                "pid": pid,
                "proto": "TCP" if conn.type == 1 else "UDP",
                "status": self._format_status(conn.status),
                "name": proc_info.get("name"),
                "cmdline": proc_info.get("cmdline"),
                "user": proc_info.get("user", "Unknown"),
                "memory": proc_info.get("memory", "N/A"),
                "threads": proc_info.get("threads", "N/A")
            }
            
            results.append(entry)
        
        return sorted(results, key=lambda x: (x["port"], x["status"] != "LISTENING"))
    
    def _get_process_info_fast(self, pid: Optional[int]) -> Dict[str, Any]:
        """Get process info with caching"""
        if not pid:
            return {"name": None, "cmdline": None}
        
        if not hasattr(self, '_proc_cache'):
            self._proc_cache = {}
        
        if pid in self._proc_cache:
            return self._proc_cache[pid]
        
        info = {"name": None, "cmdline": None, "user": "Unknown", 
                "memory": "N/A", "threads": "N/A"}
        
        if HAS_PSUTIL:
            try:
                proc = psutil.Process(pid)
                info.update({
                    "name": proc.name(),
                    "cmdline": " ".join(proc.cmdline()),
                    "user": proc.username(),
                    "memory": f"{proc.memory_info().rss / 1024 / 1024:.1f}MB",
                    "threads": proc.num_threads()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        self._proc_cache[pid] = info
        return info
    
    def _matches_search(self, proc_info: Dict[str, Any], search_substr: str) -> bool:
        """Check if process matches search criteria"""
        search_lower = search_substr.lower()
        name = proc_info.get("name", "") or ""
        cmdline = proc_info.get("cmdline", "") or ""
        
        return (search_lower in name.lower() or search_lower in cmdline.lower())
    
    def _format_status(self, status) -> str:
        """Format connection status"""
        if HAS_PSUTIL:
            status_map = {
                psutil.CONN_LISTEN: 'LISTENING',
                psutil.CONN_ESTABLISHED: 'ESTABLISHED',
                psutil.CONN_SYN_SENT: 'SYN_SENT',
                psutil.CONN_SYN_RECV: 'SYN_RECV',
                psutil.CONN_FIN_WAIT1: 'FIN_WAIT1',
                psutil.CONN_FIN_WAIT2: 'FIN_WAIT2',
                psutil.CONN_TIME_WAIT: 'TIME_WAIT',
                psutil.CONN_CLOSE: 'CLOSE',
                psutil.CONN_CLOSE_WAIT: 'CLOSE_WAIT',
                psutil.CONN_LAST_ACK: 'LAST_ACK',
                psutil.CONN_CLOSING: 'CLOSING',
                psutil.CONN_NONE: 'UDP'
            }
            return status_map.get(status, str(status))
        return str(status)
    
    def _list_ports_windows(self, filter_port: Optional[int], 
                           search_substr: Optional[str], show_all: bool) -> List[Dict[str, Any]]:
        """Windows fallback method"""
        try:
            result = subprocess.check_output(
                ["netstat", "-ano"], 
                stderr=subprocess.DEVNULL,
                timeout=10
            ).decode('utf-8', errors='ignore')
            
            entries = []
            for line in result.splitlines():
                parts = line.split()
                if len(parts) < 5 or not parts[1] or parts[0] not in ['TCP', 'UDP']:
                    continue
                
                proto = parts[0]
                local_addr = parts[1]
                state = parts[3] if proto == 'TCP' else 'UDP'
                pid_str = parts[-1]
                
                # Skip non-listening if not show_all
                if not show_all and state != 'LISTENING':
                    continue
                
                # Extract port
                try:
                    port = int(local_addr.split(':')[-1])
                    pid = int(pid_str)
                except ValueError:
                    continue
                
                if filter_port and port != filter_port:
                    continue
                
                proc_info = self._get_process_info_fast(pid)
                
                if search_substr and not self._matches_search(proc_info, search_substr):
                    continue
                
                entry = {
                    "port": port, "pid": pid, "proto": proto, "status": state,
                    "name": proc_info.get("name"), "cmdline": proc_info.get("cmdline"),
                    "user": "Unknown", "memory": "N/A", "threads": "N/A"
                }
                entries.append(entry)
            
            return sorted(entries, key=lambda x: x["port"])
            
        except subprocess.TimeoutExpired:
            print("Command timed out. Try again.")
            return []
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def _list_ports_unix(self, filter_port: Optional[int], 
                        search_substr: Optional[str], show_all: bool) -> List[Dict[str, Any]]:
        """Unix fallback method"""
        cmd = ["lsof", "-nP", "-i"] if show_all else ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]
        
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode()
            entries = []
            
            for line in result.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 9:
                    continue
                
                command = parts[0]
                pid = int(parts[1])
                name_field = " ".join(parts[8:])
                
                # Extract port
                port = None
                if ":" in name_field:
                    try:
                        port = int(name_field.split(":")[-1].split()[0])
                    except ValueError:
                        continue
                
                if filter_port and port != filter_port:
                    continue
                
                status = "LISTENING" if "(LISTEN)" in name_field else "ESTABLISHED"
                
                proc_info = {"name": command, "cmdline": None}
                if search_substr:
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            proc_info["cmdline"] = f.read().replace(b"\x00", b" ").decode(errors="ignore")
                    except:
                        pass
                
                if search_substr and not self._matches_search(proc_info, search_substr):
                    continue
                
                entry = {
                    "port": port, "pid": pid, "proto": "TCP", "status": status,
                    "name": command, "cmdline": proc_info.get("cmdline"),
                    "user": "Unknown", "memory": "N/A", "threads": "N/A"
                }
                entries.append(entry)
            
            return sorted(entries, key=lambda x: x["port"] or 0)
            
        except subprocess.TimeoutExpired:
            print("Command timed out. Try again.")
            return []
        except Exception as e:
            print(f"Error: {e}")
            return []


def display_results(entries: List[Dict[str, Any]]):
    """Display results with Rich if available, otherwise fallback"""
    # Filter application ports (skip system ports)
    app_entries = [e for e in entries if e.get("port") and e.get("name") 
                   and e.get("name").lower() not in ["system", ""]]
    
    if not app_entries:
        print("No application ports found.")
        return
    
    if HAS_RICH:
        _display_rich(app_entries)
    else:
        _display_fallback(app_entries)


def _display_rich(entries: List[Dict[str, Any]]):
    """Rich table display"""
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    
    table.add_column("Port", justify="center", style="cyan", width=8)
    table.add_column("Protocol", justify="center", style="green", width=8)
    table.add_column("Process", style="white", width=25)
    table.add_column("PID", justify="center", style="yellow", width=8)
    table.add_column("Memory", justify="right", style="magenta", width=10)
    table.add_column("Status", justify="center", style="yellow", width=12)

    
    for entry in entries:
        port = str(entry.get("port", ""))
        proto = entry.get("proto", "TCP")
        name = entry.get("name", "Unknown")[:25]
        pid = str(entry.get("pid", ""))
        memory = entry.get("memory", "N/A")
        status = entry.get("status", "UNKNOWN")

        
        table.add_row(port, proto, name, pid, memory,status)
    
    console.print(table)


def _display_fallback(entries: List[Dict[str, Any]]):
    """Simple table display"""
    header = f"{'Port':>6} | {'Proto':>6} | {'Status':>12} | {'Process':>25} | {'PID':>8} | {'Memory':>10}"
    print("─" * len(header))
    print(header)
    print("─" * len(header))
    
    for entry in entries:
        port = entry.get("port", "")
        proto = entry.get("proto", "TCP")
        status = entry.get("status", "UNKNOWN")
        name = (entry.get("name", "Unknown") or "Unknown")[:25]
        pid = entry.get("pid", "")
        memory = entry.get("memory", "N/A")
        
        print(f"{port:>6} | {proto:>6} | {status:>12} | {name:>25} | {pid:>8} | {memory:>10}")


def main():
    parser = argparse.ArgumentParser(description="Fast port scanner and process manager")
    parser.add_argument("-p", "--port", type=int, help="Filter for specific port")
    parser.add_argument("-s", "--search", type=str, help="Search processes by name/command")
    parser.add_argument("-a", "--all", action="store_true", help="Show all connections (not just listening)")
    parser.add_argument("-k", "--kill", type=int, help="Kill process using specified port")
    
    args = parser.parse_args()
    
    scanner = PortScanner()
    

    if args.kill:
        scanner.kill_process_by_port(args.kill)
        return
    
    mode = "all connections" if args.all else "listening ports only"
    print(f"Scanning {mode}...")
    
    entries = scanner.list_ports(
        filter_port=args.port,
        search_substr=args.search,
        show_all=args.all
    )
    
    display_results(entries)


if __name__ == "__main__":
    main()