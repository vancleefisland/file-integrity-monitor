"""Watch protected files and report changes against an approved SHA-256 baseline"""
import argparse
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import sys
import threading
import time
from uuid import uuid4
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

def utc_now():
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def linked(path):
    """Return whether a path is a symbolic link or junction."""
    return path.is_symlink() or path.is_junction()

def excluded(name, patterns):
    """Match relative file names against the configured glob patterns."""
    return any(fnmatch.fnmatch(name, pattern) or (
        pattern.startswith("**/") and fnmatch.fnmatch(name, pattern[3:])) for pattern in patterns)

def load_config(path):
    """Read configuration and validate the settings used by the monitor."""
    config = json.loads(path.read_text(encoding="utf-8"))
    fields = {"protected_root", "baseline_path", "alert_path", "exclusions", "chunk_size_bytes",
              "debounce_seconds", "reconcile_interval_seconds", "rules"}
    if not isinstance(config, dict) or set(config) != fields:
        raise ValueError("Configuration fields are missing or unsupported")
    patterns = config["exclusions"]
    if not isinstance(patterns, list) or any(not isinstance(p, str) or not p for p in patterns):
        raise ValueError("exclusions must be a list of nonempty glob patterns")
    for key, low, high in [("chunk_size_bytes", 4096, 16777216), ("debounce_seconds", 0, 10),
                           ("reconcile_interval_seconds", 0.1, 3600)]:
        value = config[key]
        if type(value) not in (int, float) or not low <= value <= high:
            raise ValueError(f"Invalid {key}")
    if type(config["chunk_size_bytes"]) is not int:
        raise ValueError("chunk_size_bytes must be an integer")
    if config["debounce_seconds"] >= config["reconcile_interval_seconds"]:
        raise ValueError("Debounce must be shorter than the reconciliation interval")
    rules = config["rules"]
    if not isinstance(rules, dict) or set(rules) != {
            "FILE_ADDED", "CONTENT_MODIFIED", "FILE_DELETED"}:
        raise ValueError("Configuration must define all three event rules")
    for rule in rules.values():
        if not isinstance(rule, dict) or set(rule) != {"id", "name", "severity"}:
            raise ValueError("Each rule needs id, name and severity")
        if any(not isinstance(value, str) or not value.strip() for value in rule.values()):
            raise ValueError("Rule values must be nonempty strings")
        if rule["severity"] not in ("LOW", "MEDIUM", "HIGH"):
            raise ValueError("Invalid rule severity")
    if len({rule["id"] for rule in rules.values()}) != 3:
        raise ValueError("Rule IDs must be unique")
    for key in ("protected_root", "baseline_path", "alert_path"):
        value = config[key]
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} must be a nonempty path")
        candidate = Path(os.path.abspath(path.parent / value))
        if any(linked(item) for item in (candidate, *candidate.parents)):
            raise ValueError("Configured paths cannot use symbolic links or junctions")
        config[key] = candidate
    root = config["protected_root"]
    outputs = [config["baseline_path"], config["alert_path"]]
    if not root.is_dir() or root == Path(root.anchor):
        raise ValueError("protected_root must be an existing asset directory")
    if path.is_relative_to(root) or Path(__file__).resolve().is_relative_to(root):
        raise ValueError("Protected assets must be separate from the program and configuration")
    if len({path, *outputs}) != 3 or any(item.is_relative_to(root) for item in outputs):
        raise ValueError("Output files must be distinct and outside the protected directory")
    return config

def hash_file(path, chunk_size):
    """Read a regular file in chunks and return its digest, size and modification time."""
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(chunk_size):
            digest.update(block)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns):
        raise OSError("File changed during reading")
    return {"sha256": digest.hexdigest(), "size": after.st_size, "mtime_ns": after.st_mtime_ns}

def scan_files(config, previous=None, strict=False):
    """Scan included files, preserving earlier observations where reads fail."""
    root = config["protected_root"]
    if not root.is_dir() or linked(root):
        raise OSError("Protected directory is unavailable")
    files, failed = {}, []

    def unreadable(error):
        """Record a subtree that could not be enumerated."""
        name = Path(error.filename).relative_to(root).as_posix()
        failed.append("" if name == "." else name)
        logging.warning("Cannot enumerate %s; deferred", name)

    for folder, directories, names in os.walk(root, onerror=unreadable, followlinks=False):
        directory = Path(folder)
        directories[:] = sorted(name for name in directories
                                if not linked(directory / name) and not excluded(
                                    (directory / name).relative_to(root).as_posix() + "/",
                                    config["exclusions"]))
        for name in sorted(names):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            if linked(path) or excluded(relative, config["exclusions"]):
                continue
            try:
                if path.is_file():
                    files[relative] = hash_file(path, config["chunk_size_bytes"])
            except OSError as error:
                failed.append(relative)
                logging.warning("Cannot read %s (%s); deferred", relative, type(error).__name__)
    if strict and failed:
        raise ValueError("Cannot approve a baseline with unreadable files")
    for name, record in (previous or {}).items():
        if any(not prefix or name == prefix or name.startswith(prefix + "/") for prefix in failed):
            files.setdefault(name, record)
    return dict(sorted(files.items()))

def build_baseline(config):
    """Create an approved manifest from a complete scan."""
    files = scan_files(config, strict=True)
    return {"baseline_id": uuid4().hex, "created_at": utc_now(), "algorithm": "sha256",
            "exclusions": config["exclusions"], "files": files}

def load_baseline(config):
    """Read the approved manifest and reject invalid policy or file records."""
    baseline = json.loads(config["baseline_path"].read_text(encoding="utf-8"))
    fields = {"baseline_id", "created_at", "algorithm", "exclusions", "files"}
    if not isinstance(baseline, dict) or set(baseline) != fields:
        raise ValueError("Invalid baseline fields")
    if baseline["algorithm"] != "sha256" or baseline["exclusions"] != config["exclusions"]:
        raise ValueError("Baseline policy differs; review before rebuilding")
    if not isinstance(baseline["baseline_id"], str) or len(baseline["baseline_id"]) != 32:
        raise ValueError("Invalid baseline identifier")
    if not isinstance(baseline["created_at"], str) or not baseline["created_at"].endswith("Z"):
        raise ValueError("Invalid baseline timestamp")
    datetime.fromisoformat(baseline["created_at"])
    if not isinstance(baseline["files"], dict):
        raise ValueError("Baseline files must be an object")
    for name, record in baseline["files"].items():
        if not name or Path(name).is_absolute() or ".." in Path(name).parts or ":" in name:
            raise ValueError("Invalid baseline relative path")
        if not isinstance(record, dict) or set(record) != {"sha256", "size", "mtime_ns"}:
            raise ValueError("Invalid baseline file record")
        digest = record["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(
                letter not in "0123456789abcdef" for letter in digest):
            raise ValueError("Invalid SHA-256 digest")
        if any(type(record[key]) is not int or record[key] < 0 for key in ("size", "mtime_ns")):
            raise ValueError("Invalid baseline file metadata")
    return baseline

def changes_between(previous, current):
    """Return additions, deletions and changed content between two file inventories."""
    changes = [("FILE_DELETED", name) for name in sorted(previous.keys() - current.keys())]
    changes.extend(("FILE_ADDED", name) for name in sorted(current.keys() - previous.keys()))
    changes.extend(("CONTENT_MODIFIED", name) for name in sorted(previous.keys() & current.keys())
                   if previous[name]["sha256"] != current[name]["sha256"])
    return changes

def reconcile(config, baseline, previous):
    """Compare current files and append baseline-aware JSON alerts."""
    current = scan_files(config, previous)
    changes = changes_between(previous, current)
    if changes:
        with config["alert_path"].open("a", encoding="utf-8") as stream:
            for event, name in changes:
                rule = config["rules"][event]
                approved = baseline["files"].get(name, {}).get("sha256")
                new_hash = current.get(name, {}).get("sha256")
                alert = {"timestamp": utc_now(), "severity": rule["severity"], "event_type": event,
                         "rule_id": rule["id"], "rule_name": rule["name"], "source_path": name,
                         "old_sha256": previous.get(name, {}).get("sha256"),
                         "new_sha256": new_hash, "baseline_sha256": approved,
                         "baseline_status": "MATCH" if new_hash == approved else "DIFFERENT",
                         "baseline_id": baseline["baseline_id"]}
                stream.write(json.dumps(alert) + "\n")
                stream.flush()
    return current, len(changes)

class integrity_handler(FileSystemEventHandler):
    """Signal filesystem activity to the monitoring loop."""
    def __init__(self, changed):
        """Keep the activity signal used by the observer."""
        super().__init__()
        self.changed = changed
    def on_any_event(self, event):
        """Request a scan for content or name activity."""
        if event.event_type in ("created", "modified", "deleted", "moved"):
            self.changed.set()

def run_monitor(config, baseline):
    """Watch continuously, with periodic scans to recover persistent differences."""
    changed = threading.Event()
    observer = Observer()
    observer.schedule(integrity_handler(changed), str(config["protected_root"]), recursive=True)
    previous = baseline["files"]
    try:
        observer.start()
        previous, count = reconcile(config, baseline, previous)
        print("Monitoring protected files", flush=True)
        while observer.is_alive():
            if changed.wait(config["reconcile_interval_seconds"]):
                changed.clear()
                time.sleep(config["debounce_seconds"])
            previous, count = reconcile(config, baseline, previous)
        raise OSError("Filesystem observer stopped")
    finally:
        observer.stop()
        if observer.ident is not None:
            observer.join()

def main(argv=None):
    """Run baseline creation, a single scan or continuous monitoring."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--rebuild-baseline", action="store_true")
    modes.add_argument("--once", action="store_true")
    arguments = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    try:
        config = load_config(arguments.config.resolve())
        if arguments.rebuild_baseline:
            baseline = build_baseline(config)
            temporary = config["baseline_path"].with_name(config["baseline_path"].name + ".tmp")
            temporary.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
            temporary.replace(config["baseline_path"])
            print(f"Baseline saved: {len(baseline['files'])} files")
        else:
            baseline = load_baseline(config)
            if arguments.once:
                current, count = reconcile(config, baseline, baseline["files"])
                print(f"Scan complete: {count} alerts")
            else:
                run_monitor(config, baseline)
    except KeyboardInterrupt:
        print("Monitoring stopped")
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0
if __name__ == "__main__":
    sys.exit(main())
