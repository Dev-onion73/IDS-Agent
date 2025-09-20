#!/usr/bin/env python3
import os
import json
import uuid
import time
from datetime import datetime
import yaml
from client import send_event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
from threading import Thread

# === Paths & Config ===
CONFIG_FILE = "agent.yaml"
EVENT_DIR = "events"
os.makedirs(EVENT_DIR, exist_ok=True)
FILE_EVENTS_JSON = os.path.join(EVENT_DIR, "file_events.json")
NETWORK_EVENTS_JSON = os.path.join(EVENT_DIR, "network_events.json")

with open(CONFIG_FILE) as f:
    config = yaml.safe_load(f)

DEVICE_ID = config.get("device_id", "agent-123")
FILE_PATHS = config.get("file_monitor", {}).get("paths", [])
NETWORK_MONITOR_ENABLED = config.get("network_monitor", {}).get("enabled", False)

# === Local storage ===
def save_event_locally(event_json):
    filename = FILE_EVENTS_JSON if event_json["type"] == "file_event" else NETWORK_EVENTS_JSON
    with open(filename, "a") as f:
        f.write(json.dumps(event_json) + "\n")

# === File Monitoring ===
class FileEventHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return
        if FILE_PATHS and not any(event.src_path.startswith(p) for p in FILE_PATHS):
            return

        event_json = {
            "id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "type": "file_event",
            "details": {
                "path": event.src_path,
                "action": event.event_type,
                "process": "unknown"
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        send_event(event_json)
        save_event_locally(event_json)

# === Network Monitoring via C program ===
def monitor_network_c(c_program_path="./ebpf"):
    """Launch the C network monitor and read JSON events from its stdout."""
    if not os.path.isfile(c_program_path):
        print(f"[ERROR] C network monitor not found at {c_program_path}")
        return

    proc = subprocess.Popen(
        [c_program_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # Line buffered
    )

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            event_json = json.loads(line)
            event_json["device_id"] = DEVICE_ID  # Add device ID
            send_event(event_json)
            save_event_locally(event_json)
        except json.JSONDecodeError:
            print(f"[WARNING] Could not decode JSON from C monitor: {line}")

# === Main ===
if __name__ == "__main__":
    print("Daemon started with Watchdog + C network monitoring.")

    # Setup file observers
    observers = []
    if config.get("file_monitor", {}).get("enabled", False):
        for path in FILE_PATHS:
            if not os.path.exists(path):
                print(f"[WARNING] File path does not exist: {path}")
                continue
            handler = FileEventHandler()
            observer = Observer()
            observer.schedule(handler, path=path, recursive=True)
            observer.start()
            observers.append(observer)

    # Start C network monitor in a separate thread
    network_thread = None
    if NETWORK_MONITOR_ENABLED:
        network_thread = Thread(target=monitor_network_c, args=("./mon",), daemon=True)
        network_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Daemon stopped.")
        for obs in observers:
            obs.stop()
            obs.join()
