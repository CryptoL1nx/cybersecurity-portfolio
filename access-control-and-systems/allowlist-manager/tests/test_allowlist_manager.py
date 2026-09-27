"""
Unit tests for allowlist_manager.py.

Run with: pytest -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from allowlist_manager import parse_ip_list, reconcile, write_allow_list_safely  # noqa: E402


# --------------------------------------------------------------------------- #
# parse_ip_list
# --------------------------------------------------------------------------- #

def test_parse_ip_list_accepts_valid_ipv4():
    valid, malformed = parse_ip_list("192.168.1.1\n10.0.0.5\n")
    assert valid == ["192.168.1.1", "10.0.0.5"]
    assert malformed == []


def test_parse_ip_list_accepts_valid_ipv6():
    valid, malformed = parse_ip_list("2001:db8::1\n::1\n")
    assert valid == ["2001:db8::1", "::1"]
    assert malformed == []


def test_parse_ip_list_rejects_malformed_entries():
    valid, malformed = parse_ip_list("192.168.1.1\n999.999.999.999\nnot-an-ip\n10.0.0.5")
    assert valid == ["192.168.1.1", "10.0.0.5"]
    assert malformed == ["999.999.999.999", "not-an-ip"]


def test_parse_ip_list_skips_blank_lines():
    valid, malformed = parse_ip_list("192.168.1.1\n\n\n10.0.0.5\n")
    assert valid == ["192.168.1.1", "10.0.0.5"]
    assert malformed == []


def test_parse_ip_list_strips_whitespace():
    valid, malformed = parse_ip_list("  192.168.1.1  \n\t10.0.0.5\t\n")
    assert valid == ["192.168.1.1", "10.0.0.5"]


# --------------------------------------------------------------------------- #
# reconcile — core removal logic
# --------------------------------------------------------------------------- #

def test_reconcile_removes_matching_ips():
    allow_text = "192.168.1.1\n192.168.1.2\n192.168.1.3\n"
    remove_text = "192.168.1.2\n"
    result = reconcile(allow_text, remove_text)

    assert result.remaining == ["192.168.1.1", "192.168.1.3"]
    assert result.removed == ["192.168.1.2"]
    assert result.not_found == []
    assert result.original_count == 3
    assert result.final_count == 2


def test_reconcile_no_matches_leaves_allow_list_unchanged():
    allow_text = "192.168.1.1\n192.168.1.2\n"
    remove_text = "10.0.0.9\n"
    result = reconcile(allow_text, remove_text)

    assert result.remaining == ["192.168.1.1", "192.168.1.2"]
    assert result.removed == []
    assert result.not_found == ["10.0.0.9"]


def test_reconcile_reports_remove_list_entry_not_in_allow_list():
    allow_text = "192.168.1.1\n"
    remove_text = "192.168.1.1\n10.10.10.10\n"
    result = reconcile(allow_text, remove_text)

    assert result.removed == ["192.168.1.1"]
    assert result.not_found == ["10.10.10.10"]


def test_reconcile_deduplicates_allow_list():
    allow_text = "192.168.1.1\n192.168.1.1\n192.168.1.2\n"
    remove_text = ""
    result = reconcile(allow_text, remove_text)

    assert result.remaining == ["192.168.1.1", "192.168.1.2"]
    assert result.duplicates_in_allow_list == ["192.168.1.1"]


def test_reconcile_handles_empty_remove_list():
    allow_text = "192.168.1.1\n192.168.1.2\n"
    remove_text = ""
    result = reconcile(allow_text, remove_text)

    assert result.remaining == ["192.168.1.1", "192.168.1.2"]
    assert result.removed == []


def test_reconcile_handles_empty_allow_list():
    allow_text = ""
    remove_text = "192.168.1.1\n"
    result = reconcile(allow_text, remove_text)

    assert result.remaining == []
    assert result.original_count == 0
    assert result.not_found == ["192.168.1.1"]


def test_reconcile_removing_everything_leaves_empty_list():
    allow_text = "192.168.1.1\n192.168.1.2\n"
    remove_text = "192.168.1.1\n192.168.1.2\n"
    result = reconcile(allow_text, remove_text)

    assert result.remaining == []
    assert result.removed == ["192.168.1.1", "192.168.1.2"]


def test_reconcile_surfaces_malformed_entries_without_crashing():
    allow_text = "192.168.1.1\nnot-an-ip\n192.168.1.2\n"
    remove_text = "also-not-an-ip\n192.168.1.2\n"
    result = reconcile(allow_text, remove_text)

    assert result.remaining == ["192.168.1.1"]
    assert result.malformed_in_allow_list == ["not-an-ip"]
    assert result.malformed_in_remove_list == ["also-not-an-ip"]


# --------------------------------------------------------------------------- #
# write_allow_list_safely — file I/O safety
# --------------------------------------------------------------------------- #

def test_write_allow_list_safely_writes_new_content(tmp_path):
    allow_list = tmp_path / "allow_list.txt"
    allow_list.write_text("192.168.1.1\n192.168.1.2\n")

    write_allow_list_safely(allow_list, ["192.168.1.1"])

    assert allow_list.read_text() == "192.168.1.1\n"


def test_write_allow_list_safely_creates_backup(tmp_path):
    allow_list = tmp_path / "allow_list.txt"
    original_content = "192.168.1.1\n192.168.1.2\n"
    allow_list.write_text(original_content)

    backup_path = write_allow_list_safely(allow_list, ["192.168.1.1"])

    assert backup_path.exists()
    assert backup_path.read_text() == original_content


def test_write_allow_list_safely_handles_empty_result(tmp_path):
    allow_list = tmp_path / "allow_list.txt"
    allow_list.write_text("192.168.1.1\n")

    write_allow_list_safely(allow_list, [])

    assert allow_list.read_text() == ""


def test_write_allow_list_safely_no_temp_file_left_behind(tmp_path):
    allow_list = tmp_path / "allow_list.txt"
    allow_list.write_text("192.168.1.1\n")

    write_allow_list_safely(allow_list, ["192.168.1.1"])

    leftover_tmp = allow_list.with_suffix(allow_list.suffix + ".tmp")
    assert not leftover_tmp.exists()
