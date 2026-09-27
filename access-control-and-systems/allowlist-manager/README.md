# Allow-List Access Review Tool

A Python command-line tool for de-provisioning IP addresses from a network allow list — built around a real security requirement: revoking access is only a control if it's validated, previewable, and auditable, not just a file edit.

## What it does

Given an **allow list** (IP addresses currently permitted into a restricted subnetwork) and a **remove list** (IP addresses whose access should be revoked), the tool reconciles the two and writes the updated allow list, with input validation, a dry-run mode, an audit trail, and a safe write path.

```bash
# Preview the change without writing anything
python allowlist_manager.py --allow-list sample_data/allow_list.txt --remove-list sample_data/remove_list.txt --dry-run

# Apply the change and keep a timestamped audit log
python allowlist_manager.py --allow-list sample_data/allow_list.txt --remove-list sample_data/remove_list.txt --log-file audit.log
```

The `--allow-list` and `--remove-list` flags take a path to any file with one IP address per line — `sample_data/` just holds a ready-made example. Point them at your own files (or paths) to use it on real data. On Windows, use backslashes or forward slashes interchangeably, e.g. `sample_data\allow_list.txt`.

## Sample output

Given the sample `allow_list.txt` (6 entries) and `remove_list.txt` (3 entries, one of which — `192.168.1.99` — isn't actually on the allow list) in `sample_data/`, a dry run produces:

```
$ python allowlist_manager.py --allow-list sample_data/allow_list.txt --remove-list sample_data/remove_list.txt --dry-run

2026-09-27T09:55:31Z [INFO] [DRY RUN] Allow list reconciliation starting with 6 entries.
2026-09-27T09:55:31Z [INFO] Removed 2 IP(s): ['192.168.1.15', '192.168.1.47']
2026-09-27T09:55:31Z [WARNING] 1 IP(s) on the remove list were not present in the allow list (already removed, or a possible typo): ['192.168.1.99']
2026-09-27T09:55:31Z [INFO] [DRY RUN] Final allow list size: 4 (was 6).
2026-09-27T09:55:31Z [INFO] Dry run complete. No files were modified.
```

Note that the tool surfaces the mismatched entry as a warning instead of silently ignoring it — in a real access review, an IP that's requested for removal but isn't found is worth someone's attention, whether that means the access was already revoked elsewhere or there's a typo masking access that's still live. Dropping `--dry-run` applies the same reconciliation for real: it backs up the current allow list to a timestamped file before writing, then atomically replaces it, so a crash mid-write can never leave the file truncated or empty.

## Design choices

| Feature | Why it matters here |
|---|---|
| **Real IP validation** (`ipaddress` module, not regex) | A malformed or corrupted entry in either input file should be caught and reported, not silently mishandled or allowed to crash the run partway through. |
| **Dry-run mode** | Access control changes should be previewable before they're applied — standard practice for anything that touches production authorization. |
| **Audit logging** | An access change with no record of what changed, when, and what was requested but not found doesn't hold up to a compliance review. This maps to NIST SP 800-53 **AC-2 (Account Management)**, which expects account/access changes to be logged. |
| **"Not found" reporting** | Flags remove-list entries that aren't on the allow list, since that can mean access was already revoked elsewhere, or a typo that would otherwise let stale access silently persist. |
| **Atomic, backed-up writes** | The allow list gates access to a restricted subnetwork; the tool backs up the previous version and writes the new one atomically (write-to-temp-file, then rename) rather than overwriting in place. |
| **Duplicate detection** | Detects and reports duplicate entries in the allow list rather than assuming the input is clean. |
| **17 unit tests** (`pytest`) | Covers the reconciliation logic (removal, no-match, duplicates, empty lists) and the file-writing safety guarantees (backup created, atomic write, no leftover temp file). |

## Project structure

```
allowlist-manager/
├── allowlist_manager.py      # CLI tool and core logic
├── tests/
│   └── test_allowlist_manager.py
├── sample_data/
│   ├── allow_list.txt
│   └── remove_list.txt
└── README.md
```

## Running it yourself

```bash
pip install pytest          # only needed to run the test suite
python -m pytest tests/ -v  # 17 tests, all passing

python allowlist_manager.py \
  --allow-list sample_data/allow_list.txt \
  --remove-list sample_data/remove_list.txt \
  --dry-run
```

## Honest limitations

This works on flat text files, not a live firewall, IdP, or directory service — a production version would call an API (a cloud security group, an IAM system) rather than editing a file by hand. It also only supports individual IP addresses, not CIDR ranges. Both are natural next steps if this were extended into something a team actually deployed, rather than a focused piece demonstrating the underlying engineering practices: validation, auditability, safe writes, and test coverage.

## Context

Originally based on a short Python file-handling exercise (read an allow list, remove entries found on a separate remove list, write the result back). Rebuilt as a CLI tool with the validation, safety, and audit practices described above.
