#!/usr/bin/env python3
"""Command-line entry point for openports.

Examples:
    openports                # list listening ports
    openports -p 3000        # only port 3000
    openports -s react       # processes matching 'react'
    openports -a             # include non-listening connections
    openports -k 3000        # kill processes on port 3000
    openports --json         # machine-readable output
"""

import argparse
import sys

from . import __version__, display, formats
from .scanner import PortScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openports",
        description="Fast port scanner and process manager")
    parser.add_argument("-p", "--port", type=int,
                        help="Filter for a specific port")
    parser.add_argument("-s", "--search", type=str,
                        help="Search processes by name/command")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Show all connections, not just listening")
    parser.add_argument("-k", "--kill", type=int,
                        help="Kill processes using the specified port")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip the kill confirmation prompt")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show full command lines")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--csv", action="store_true",
                        help="Output results as CSV")
    parser.add_argument("--version", action="version",
                        version="openports {}".format(__version__))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    scanner = PortScanner()

    if args.kill is not None:
        ok = scanner.kill_port(args.kill, assume_yes=args.yes)
        return 0 if ok else 1

    machine = args.json or args.csv
    if not machine:
        mode = "all connections" if args.all else "listening ports"
        print("Scanning {}...".format(mode), file=sys.stderr)

    entries = scanner.list_ports(
        filter_port=args.port, search=args.search, show_all=args.all)

    if args.json:
        print(formats.to_json(entries))
    elif args.csv:
        print(formats.to_csv(entries), end="")
    else:
        display.render(entries, verbose=args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
