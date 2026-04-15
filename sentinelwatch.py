#!/usr/bin/env python3
"""
SentinelWatch - A lightweight file integrity monitor for blue-team/home-lab use.

Features:
- Create a baseline of file hashes for a directory
- Scan later to detect added, removed, and modified files
- Ignore file patterns and directories
- Export results as JSON
- Colorized terminal output
- Works with standard library only

Example:
    python sentinelwatch.py baseline C:\Users\You\Documents --db baseline.json
    python sentinelwatch.py scan C:\Users\You\Documents --db baseline.json
    python sentinelwatch.py scan C:\Users\You\Documents --db baseline.json --json report.json

Great for:
- Detecting ransomware-style file changes in a lab
- Monitoring config directories
- Demonstrating hashing, integrity monitoring, and incident-response basics
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

DEFAULT_HASH = "sha256"
DEFAULT_EXCLUDES = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
}


class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


@dataclass
class FileRecord:
    path: str
    size: int
    mtime: float
    hash_algorithm: str
    digest: str


@dataclass
class ScanResult:
    scanned_at: float
    root: str
    added: List[str]
    removed: List[str]
    modified: List[str]
    unchanged: int
    errors: List[str]


def supports_color() -> bool:
    return sys.stdout.isatty() and os.name != "nt" or "ANSICON" in os.environ or "WT_SESSION" in os.environ


USE_COLOR = supports_color()


def colorize(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{Color.RESET}"


def human_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def normalize_path(path: Path, root: Path) -> str:
    return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")


def hash_file(path: Path, algorithm: str = DEFAULT_HASH, chunk_size: int = 1024 * 1024) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def should_exclude(path: Path, root: Path, excludes: Set[str], ignore_patterns: List[str]) -> bool:
    rel = normalize_path(path, root)
    parts = set(rel.split("/"))

    if parts & excludes:
        return True

    for pattern in ignore_patterns:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern):
            return True

    return False


def walk_files(root: Path, excludes: Set[str], ignore_patterns: List[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        current_dir = Path(dirpath)

        dirnames[:] = [
            d for d in dirnames
            if not should_exclude(current_dir / d, root, excludes, ignore_patterns)
        ]

        for filename in filenames:
            file_path = current_dir / filename
            if should_exclude(file_path, root, excludes, ignore_patterns):
                continue
            yield file_path


def build_baseline(root: Path, algorithm: str, excludes: Set[str], ignore_patterns: List[str]) -> Tuple[Dict[str, FileRecord], List[str]]:
    baseline: Dict[str, FileRecord] = {}
    errors: List[str] = []

    for file_path in walk_files(root, excludes, ignore_patterns):
        try:
            stat = file_path.stat()
            rel = normalize_path(file_path, root)
            baseline[rel] = FileRecord(
                path=rel,
                size=stat.st_size,
                mtime=stat.st_mtime,
                hash_algorithm=algorithm,
                digest=hash_file(file_path, algorithm),
            )
        except Exception as exc:
            errors.append(f"{file_path}: {exc}")

    return baseline, errors


def save_baseline(db_path: Path, root: Path, baseline: Dict[str, FileRecord], errors: List[str]) -> None:
    payload = {
        "metadata": {
            "root": str(root.resolve()),
            "created_at": time.time(),
            "tool": "SentinelWatch",
            "version": "1.0.0",
        },
        "files": {path: asdict(record) for path, record in baseline.items()},
        "errors": errors,
    }
    db_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_baseline(db_path: Path) -> Tuple[Dict[str, FileRecord], Dict[str, object]]:
    payload = json.loads(db_path.read_text(encoding="utf-8"))
    files = {
        path: FileRecord(**record)
        for path, record in payload.get("files", {}).items()
    }
    metadata = payload.get("metadata", {})
    return files, metadata


def compare_baseline(root: Path, old: Dict[str, FileRecord], algorithm: str, excludes: Set[str], ignore_patterns: List[str]) -> ScanResult:
    current, errors = build_baseline(root, algorithm, excludes, ignore_patterns)

    old_paths = set(old.keys())
    current_paths = set(current.keys())

    added = sorted(current_paths - old_paths)
    removed = sorted(old_paths - current_paths)

    modified: List[str] = []
    unchanged = 0

    for path in sorted(old_paths & current_paths):
        if old[path].digest != current[path].digest:
            modified.append(path)
        else:
            unchanged += 1

    return ScanResult(
        scanned_at=time.time(),
        root=str(root.resolve()),
        added=added,
        removed=removed,
        modified=modified,
        unchanged=unchanged,
        errors=errors,
    )


def print_banner() -> None:
    title = colorize("SentinelWatch", Color.CYAN)
    subtitle = colorize("Lightweight File Integrity Monitoring", Color.BLUE)
    print(f"{Color.BOLD if USE_COLOR else ''}{title}{Color.RESET if USE_COLOR else ''} - {subtitle}")
    print()


def print_result(result: ScanResult) -> None:
    print_banner()
    print(f"Scan time:  {human_time(result.scanned_at)}")
    print(f"Root path:  {result.root}")
    print()

    print(colorize(f"Added files:    {len(result.added)}", Color.GREEN))
    for item in result.added[:25]:
        print(f"  + {item}")
    if len(result.added) > 25:
        print(f"  ... and {len(result.added) - 25} more")

    print(colorize(f"Removed files:  {len(result.removed)}", Color.YELLOW))
    for item in result.removed[:25]:
        print(f"  - {item}")
    if len(result.removed) > 25:
        print(f"  ... and {len(result.removed) - 25} more")

    print(colorize(f"Modified files: {len(result.modified)}", Color.RED))
    for item in result.modified[:25]:
        print(f"  * {item}")
    if len(result.modified) > 25:
        print(f"  ... and {len(result.modified) - 25} more")

    print(f"Unchanged:      {result.unchanged}")
    print(f"Errors:         {len(result.errors)}")
    if result.errors:
        print()
        print(colorize("Read/scan errors:", Color.YELLOW))
        for err in result.errors[:10]:
            print(f"  ! {err}")
        if len(result.errors) > 10:
            print(f"  ... and {len(result.errors) - 10} more")


def write_report_json(path: Path, result: ScanResult) -> None:
    path.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SentinelWatch - file integrity monitor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("target", help="Directory to monitor")
        p.add_argument("--db", required=True, help="Path to baseline JSON database")
        p.add_argument("--algo", default=DEFAULT_HASH, help="Hash algorithm (sha256, sha1, md5, etc.)")
        p.add_argument(
            "--exclude",
            action="append",
            default=[],
            help="Directory names to exclude (repeatable)",
        )
        p.add_argument(
            "--ignore",
            action="append",
            default=[],
            help="Glob patterns to ignore, e.g. '*.log' or 'temp/*' (repeatable)",
        )

    p_baseline = subparsers.add_parser("baseline", help="Create a baseline database")
    add_common_flags(p_baseline)

    p_scan = subparsers.add_parser("scan", help="Scan directory against an existing baseline")
    add_common_flags(p_scan)
    p_scan.add_argument("--json", help="Write scan results to JSON report")
    p_scan.add_argument("--fail-on-change", action="store_true", help="Exit with code 2 if changes are detected")

    return parser.parse_args()


def validate_target(path_str: str) -> Path:
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"Target does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"Target is not a directory: {path}")
    return path


def main() -> int:
    args = parse_args()

    try:
        root = validate_target(args.target)
        db_path = Path(args.db)
        excludes = DEFAULT_EXCLUDES | set(args.exclude)
        ignore_patterns = list(args.ignore)

        if args.command == "baseline":
            baseline, errors = build_baseline(root, args.algo, excludes, ignore_patterns)
            save_baseline(db_path, root, baseline, errors)

            print_banner()
            print(colorize("Baseline created successfully.", Color.GREEN))
            print(f"Files tracked: {len(baseline)}")
            print(f"Database:      {db_path.resolve()}")
            print(f"Created at:    {human_time(time.time())}")
            if errors:
                print(colorize(f"Warnings:      {len(errors)} files could not be read", Color.YELLOW))
            return 0

        if args.command == "scan":
            if not db_path.exists():
                raise FileNotFoundError(f"Baseline database not found: {db_path}")

            old_baseline, metadata = load_baseline(db_path)
            result = compare_baseline(root, old_baseline, args.algo, excludes, ignore_patterns)
            print_result(result)

            if args.json:
                report_path = Path(args.json)
                write_report_json(report_path, result)
                print()
                print(f"JSON report written to: {report_path.resolve()}")

            changes_found = bool(result.added or result.removed or result.modified)
            if changes_found and args.fail_on_change:
                return 2
            return 0

        raise ValueError("Unsupported command.")

    except KeyboardInterrupt:
        print(colorize("\nOperation cancelled by user.", Color.YELLOW), file=sys.stderr)
        return 130
    except Exception as exc:
        print(colorize(f"Error: {exc}", Color.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
