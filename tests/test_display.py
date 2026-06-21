"""Tests for display filtering and truncation."""

from openports import display


def test_visible_keeps_real_process_named_system():
    entries = [{"port": 135, "name": "System"}]
    assert display._visible(entries) == entries


def test_visible_drops_rows_without_port_or_name():
    entries = [
        {"port": None, "name": None},
        {"port": 3000, "name": "node"},
    ]
    assert display._visible(entries) == [{"port": 3000, "name": "node"}]


def test_visible_keeps_port_without_name():
    entries = [{"port": 22, "name": None}]
    assert display._visible(entries) == entries


def test_cmdline_truncates_by_default():
    entry = {"cmdline": "x" * 100}
    out = display._cmdline(entry, verbose=False)
    assert len(out) <= display._CMDLINE_TRUNCATE
    assert out.endswith("…")


def test_cmdline_full_when_verbose():
    entry = {"cmdline": "x" * 100}
    assert display._cmdline(entry, verbose=True) == "x" * 100


def test_render_empty_prints_message(capsys):
    display.render([])
    assert "No listening ports found." in capsys.readouterr().out
