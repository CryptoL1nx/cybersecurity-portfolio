#!/usr/bin/env python3
"""
allowlist_manager.py

A small access-review utility for de-provisioning IP addresses from a
network allow list, built around the idea that removing access is a
security control (NIST SP 800-53 AC-2, Account Management) and should
be auditable, safe, and idempotent rather than a one-off script.

Typical use: a security analyst maintains an allow list of IP addresses
permitted to reach a restricted subnetwork (e.g., a system handling
patient records). When an employee's access should be revoked, their
IP is added to a remove list and this tool reconciles the two files.

Usage:
    python allowlist_manager.py --allow-list allow_list.txt --remove-list remove_list.txt
    python allowlist_manager.py --allow-list allow_list.txt --remove-list remove_list.txt --dry-run
    python allowlist_manager.py --allow-list allow_list.txt --remove-list remove_list.txt --log-file audit.log

Exit codes:
    0  success (including a dry run)
    1  input error (missing file, malformed IP, etc.)
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class ReconciliationResult:
    """The outcome of comparing an allow list against a remove list."""

    original_count: int
    remaining: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    not_found: list[str] = field(default_factory=list)
    malformed_in_allow_list: list[str] = field(default_factory=list)
    malformed_in_remove_list: list[str] = field(default_factory=list)
    duplicates_in_allow_list: list[str] = field(default_factory=list)

    @property
    def final_count(self) -> int:
        return len(self.remaining)


# --------------------------------------------------------------------------- #
# Core logic
# --------------------------------------------------------------------------- #

def parse_ip_list(raw_text: str) -> tuple[list[str], list[str]]:
    """
    Parse newline-separated IP addresses from raw file text.

    Returns a tuple of (valid_ips, malformed_lines). Blank lines are
    silently skipped (not treated as malformed) since they're a normal
    artifact of how these files get hand-edited.

    Validation uses the standard library's ipaddress module rather than
    a regex, so a string like "999.999.999.999" or "10.0.0" is correctly
    rejected instead of silently accepted by a permissive pattern.
    """
    valid: list[str] = []
    malformed: list[str] = []

    for line in raw_text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            valid.append(candidate)
        except ValueError:
            malformed.append(candidate)

    return valid, malformed


def reconcile(allow_list_text: str, remove_list_text: str) -> ReconciliationResult:
    """
    Compare an allow list against a remove list and compute the result
    of removing every valid, present remove-list entry from the allow
    list.

    This function is pure (no file I/O), which is what makes it
    straightforward to unit test: given two strings, it always returns
    the same result.
    """
    allow_ips, malformed_allow = parse_ip_list(allow_list_text)
    remove_ips, malformed_remove = parse_ip_list(remove_list_text)

    # Track and de-duplicate the allow list. A real allow list should not
    # contain duplicates (the original lab assumes this too), but silently
    # trusting that assumption is exactly the kind of thing that causes
    # subtle bugs later, so we detect and report it instead of assuming it.
    seen: set[str] = set()
    duplicates: list[str] = []
    deduped_allow: list[str] = []
    for ip in allow_ips:
        if ip in seen:
            duplicates.append(ip)
            continue
        seen.add(ip)
        deduped_allow.append(ip)

    remove_set = set(remove_ips)
    remaining = [ip for ip in deduped_allow if ip not in remove_set]
    removed = [ip for ip in deduped_allow if ip in remove_set]

    # An analyst who put an IP on the remove list expects it to have been
    # on the allow list. If it wasn't, that's worth surfacing explicitly
    # rather than silently doing nothing — it may mean the access was
    # already revoked, or it may mean a typo in the remove list.
    not_found = [ip for ip in remove_ips if ip not in seen]

    return ReconciliationResult(
        original_count=len(allow_ips),
        remaining=remaining,
        removed=removed,
        not_found=not_found,
        malformed_in_allow_list=malformed_allow,
        malformed_in_remove_list=malformed_remove,
        duplicates_in_allow_list=duplicates,
    )


# --------------------------------------------------------------------------- #
# File I/O (kept separate from the pure logic above, and made safe)
# --------------------------------------------------------------------------- #

def write_allow_list_safely(path: Path, ip_addresses: list[str]) -> Path:
    """
    Write the updated allow list without ever leaving the original file
    in a half-written or corrupted state.

    Two things make this "safe" compared to a naive open(path, "w"):
      1. A timestamped backup of the current file is written first, so
         a mistaken run can always be rolled back by hand.
      2. The new content is written to a temporary file in the same
         directory and then atomically renamed into place (os.replace
         semantics via Path.replace), so a crash mid-write can never
         leave the allow list truncated or empty — a real risk for a
         file that gates access to a restricted subnetwork.
    """
    backup_path = path.with_suffix(path.suffix + f".bak-{_timestamp_for_filename()}")
    if path.exists():
        shutil.copy2(path, backup_path)

    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text("\n".join(ip_addresses) + ("\n" if ip_addresses else ""), encoding="utf-8")
    tmp_path.replace(path)  # atomic on POSIX and Windows

    return backup_path


def _timestamp_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# --------------------------------------------------------------------------- #
# Audit logging
# --------------------------------------------------------------------------- #

def configure_logging(log_file: Path | None) -> logging.Logger:
    """
    Configure a logger that always writes to stderr, and additionally to
    a log file when one is given. Every run's outcome is logged with a
    UTC timestamp, which is the minimum an access-control tool needs to
    be auditable after the fact — "who was removed, when, by what run."
    """
    logger = logging.getLogger("allowlist_manager")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    formatter.converter = lambda *args: datetime.now(timezone.utc).timetuple()

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_file is not None:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def log_result(logger: logging.Logger, result: ReconciliationResult, dry_run: bool) -> None:
    mode = "DRY RUN" if dry_run else "APPLIED"
    logger.info(f"[{mode}] Allow list reconciliation starting with {result.original_count} entries.")

    if result.duplicates_in_allow_list:
        logger.warning(f"Duplicate IP(s) in allow list (de-duplicated): {result.duplicates_in_allow_list}")
    if result.malformed_in_allow_list:
        logger.warning(f"Malformed entr(y/ies) skipped in allow list: {result.malformed_in_allow_list}")
    if result.malformed_in_remove_list:
        logger.warning(f"Malformed entr(y/ies) skipped in remove list: {result.malformed_in_remove_list}")

    if result.removed:
        logger.info(f"Removed {len(result.removed)} IP(s): {result.removed}")
    else:
        logger.info("No IP addresses matched the remove list; nothing to remove.")

    if result.not_found:
        logger.warning(
            f"{len(result.not_found)} IP(s) on the remove list were not present "
            f"in the allow list (already removed, or a possible typo): {result.not_found}"
        )

    logger.info(f"[{mode}] Final allow list size: {result.final_count} (was {result.original_count}).")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reconcile a network allow list against a remove list, enforcing "
            "least-privilege access by revoking IP addresses that should no "
            "longer be permitted."
        )
    )
    parser.add_argument(
        "--allow-list", required=True, type=Path,
        help="Path to the allow list file (one IP address per line).",
    )
    parser.add_argument(
        "--remove-list", required=True, type=Path,
        help="Path to the remove list file (one IP address per line).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without writing to the allow list file.",
    )
    parser.add_argument(
        "--log-file", type=Path, default=None,
        help="Optional path to append a timestamped audit log of this run.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logger = configure_logging(args.log_file)

    if not args.allow_list.exists():
        logger.error(f"Allow list file not found: {args.allow_list}")
        return 1
    if not args.remove_list.exists():
        logger.error(f"Remove list file not found: {args.remove_list}")
        return 1

    allow_text = args.allow_list.read_text(encoding="utf-8")
    remove_text = args.remove_list.read_text(encoding="utf-8")

    result = reconcile(allow_text, remove_text)
    log_result(logger, result, dry_run=args.dry_run)

    if args.dry_run:
        logger.info("Dry run complete. No files were modified.")
        return 0

    backup_path = write_allow_list_safely(args.allow_list, result.remaining)
    logger.info(f"Allow list updated: {args.allow_list}")
    logger.info(f"Backup of previous version saved to: {backup_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
