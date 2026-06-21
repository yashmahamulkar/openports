"""Human-readable rendering of port entries."""

from typing import Any, Dict, List

try:
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Ports commonly used by local dev servers, highlighted for quick scanning.
DEV_PORTS = frozenset({
    3000, 3001, 4200, 5000, 5173, 8000, 8080, 8888, 5432, 6379, 27017,
})

_CMDLINE_TRUNCATE = 40


def _visible(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop only rows that carry neither a port nor a process name."""
    return [e for e in entries if e.get("port") is not None or e.get("name")]


def render(entries: List[Dict[str, Any]], verbose: bool = False) -> None:
    rows = _visible(entries)
    if not rows:
        print("No listening ports found.")
        return
    if HAS_RICH:
        _render_rich(rows, verbose)
    else:
        _render_plain(rows, verbose)


def _render_rich(entries: List[Dict[str, Any]], verbose: bool) -> None:
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port", justify="center", style="cyan", width=8)
    table.add_column("Proto", justify="center", style="green", width=6)
    table.add_column("Process", style="white", width=25)
    table.add_column("PID", justify="center", style="yellow", width=8)
    table.add_column("Memory", justify="right", style="magenta", width=10)
    table.add_column("Status", justify="center", style="yellow", width=12)
    table.add_column("Command", style="dim")

    for entry in entries:
        port = entry.get("port")
        port_text = "[bold green]{}[/]".format(port) if port in DEV_PORTS else str(port)
        table.add_row(
            port_text,
            entry.get("proto", "TCP"),
            (entry.get("name") or "Unknown")[:25],
            str(entry.get("pid", "")),
            entry.get("memory", "N/A"),
            entry.get("status", "UNKNOWN"),
            _cmdline(entry, verbose),
        )
    console.print(table)


def _render_plain(entries: List[Dict[str, Any]], verbose: bool) -> None:
    header = "{:>6} | {:>6} | {:>12} | {:>25} | {:>8} | {:>10}".format(
        "Port", "Proto", "Status", "Process", "PID", "Memory")
    print("-" * len(header))
    print(header)
    print("-" * len(header))
    for entry in entries:
        line = "{:>6} | {:>6} | {:>12} | {:>25} | {:>8} | {:>10}".format(
            entry.get("port", ""),
            entry.get("proto", "TCP"),
            entry.get("status", "UNKNOWN"),
            (entry.get("name") or "Unknown")[:25],
            entry.get("pid", ""),
            entry.get("memory", "N/A"),
        )
        cmd = _cmdline(entry, verbose)
        if cmd:
            line += " | " + cmd
        print(line)


def _cmdline(entry: Dict[str, Any], verbose: bool) -> str:
    cmd = entry.get("cmdline") or ""
    if verbose or len(cmd) <= _CMDLINE_TRUNCATE:
        return cmd
    return cmd[:_CMDLINE_TRUNCATE - 1] + "…"
