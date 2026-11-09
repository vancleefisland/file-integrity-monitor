"""Demonstrate file tampering in a temporary directory without altering real assets"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

def main():
    """Run the monitor against four harmless changes and check its alerts."""
    project = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="fim_demo_") as temporary:
        folder = Path(temporary)
        protected = folder / "protected"
        protected.mkdir()
        for index in range(20):
            path = protected / f"dir_{index % 5}" / f"asset_{index:02}.txt"
            path.parent.mkdir(exist_ok=True)
            path.write_text(f"approved asset {index:04}\n", encoding="utf-8")
        config = json.loads((project / "config.json").read_text(encoding="utf-8"))
        config["debounce_seconds"] = 0.05
        config["reconcile_interval_seconds"] = 0.5
        config_path = folder / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        command = [sys.executable, str(project / "fim.py"), "--config", str(config_path)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            if process.stdout.readline().strip() != "Monitoring protected files":
                raise RuntimeError("The monitor did not start")
            scenarios = [("CONTENT_MODIFIED", "dir_0/asset_00.txt"),
                         ("FILE_ADDED", "nested/new.txt"), ("FILE_DELETED", "dir_1/asset_01.txt"),
                         ("RENAME", "renamed.txt")]
            for index, (event, name) in enumerate(scenarios, 1):
                path = protected / name
                if event == "CONTENT_MODIFIED":
                    metadata = path.stat()
                    path.write_bytes(path.read_bytes().replace(b"approved", b"modified"))
                    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
                elif event == "FILE_ADDED":
                    path.parent.mkdir()
                    path.write_text("new policy\n", encoding="utf-8")
                elif event == "FILE_DELETED":
                    path.unlink()
                else:
                    (protected / "dir_2/asset_02.txt").rename(path)
                expected = {(event, name)}
                if event == "RENAME":
                    expected = {("FILE_DELETED", "dir_2/asset_02.txt"),
                                ("FILE_ADDED", "renamed.txt")}
                target_count = index if event != "RENAME" else index + 1
                deadline = time.monotonic() + 5
                alerts = []
                while len(alerts) < target_count and time.monotonic() < deadline:
                    time.sleep(0.02)
                    log = folder / "alerts.jsonl"
                    if log.exists():
                        alerts = [json.loads(line) for line in log.read_text().splitlines()]
                actual = {(item["event_type"], item["source_path"])
                          for item in alerts[-len(expected):]}
                if len(alerts) != target_count or actual != expected:
                    raise RuntimeError(f"Expected {event} for {name}")
                print(f"{event}: {name}")
            print("Detected all four controlled changes")
        finally:
            if process.poll() is None:
                process.send_signal(signal.CTRL_BREAK_EVENT)
            process.communicate(timeout=5)
        if process.returncode != 0:
            raise RuntimeError("The monitor did not shut down cleanly")
    return 0
if __name__ == "__main__":
    sys.exit(main())
