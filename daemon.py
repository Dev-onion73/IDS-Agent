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
from scapy.all import sniff, TCP, IP

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
NETWORK_PORTS = config.get("network_monitor", {}).get("ports", [])

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
            "device_id": DEVICE_ID,
            "type": "file_event",
            "path": event.src_path,
            "action": event.event_type,
            "process": "unknown",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        send_event(event_json)
        save_event_locally(event_json)

# === Network Monitoring ===
def handle_packet(packet):
    """Event-driven network packet handler via Scapy."""
    if TCP in packet and packet[TCP].dport in NETWORK_PORTS:
        event_json = {
            "id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "type": "network_event",
            "details": {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "sport": packet[TCP].sport,
                "dport": packet[TCP].dport,
                "protocol": "TCP",
                "action": "connect"
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        send_event(event_json)
        save_event_locally(event_json)

def start_network_sniffer():
    """Start Scapy sniffing in the background."""
    from threading import Thread
    sniff_thread = Thread(
        target=sniff,
        kwargs={
            "filter": "tcp",
            "prn": handle_packet,
            "store": False
        },
        daemon=True
    )
    sniff_thread.start()
    return sniff_thread

# === Main loop ===
if __name__ == "__main__":
    print("Daemon started with Watchdog + Scapy monitoring.")

    # Setup file observers
    observers = []
    if config.get("file_monitor", {}).get("enabled", False):
        for path in FILE_PATHS:
            handler = FileEventHandler()
            observer = Observer()
            observer.schedule(handler, path=path, recursive=True)
            observer.start()
            observers.append(observer)

    # Setup network sniffer
    sniff_thread = None
    if config.get("network_monitor", {}).get("enabled", False):
        sniff_thread = start_network_sniffer()

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Daemon stopped.")
        # Stop file observers
        for obs in observers:
            obs.stop()
            obs.join()
