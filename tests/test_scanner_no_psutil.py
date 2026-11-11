"""Regression test for issue #3: psutil import failure breaks test mocking.

When the optional psutil extra is not installed, ``scanner`` used to leave
the ``psutil`` name undefined on the module, so ``mock.patch.object(
scanner, "psutil", ...)`` raised::

    AttributeError: <module 'openports.scanner'> does not have the
    attribute 'psutil'

This runs a fresh interpreter with the psutil import blocked so it passes
whether or not psutil is installed in the test environment.
"""

import subprocess
import sys

_NO_PSUTIL_SCRIPT = """
import builtins
import unittest.mock

_real_import = builtins.__import__


def _no_psutil(name, *args, **kwargs):
    if name == "psutil" or name.startswith("psutil."):
        raise ImportError("psutil blocked for test")
    return _real_import(name, *args, **kwargs)


builtins.__import__ = _no_psutil

import openports.scanner as scanner

assert scanner.HAS_PSUTIL is False, "expected HAS_PSUTIL False without psutil"
assert hasattr(scanner, "psutil"), (
    "scanner module must define a 'psutil' attribute even when the "
    "optional psutil extra is not installed (issue #3)"
)

# The exact pattern from the issue: patching scanner.psutil must work.
with unittest.mock.patch.object(scanner, "psutil"):
    pass

# And the fallback listing path must still run with HAS_PSUTIL False.
scanner.PortScanner().list_ports()
"""


def test_mockable_psutil_attribute_without_psutil_installed():
    result = subprocess.run(
        [sys.executable, "-c", _NO_PSUTIL_SCRIPT],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "scanner.psutil must exist and be patchable without psutil:\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
