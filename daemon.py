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
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Ether, Raw, conf
from threading import Thread
import subprocess

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

# === NFQUEUE Network Monitoring ===
def setup_iptables(queue_num=1):
    """Add iptables rule to send TCP packets to NFQUEUE."""
    for port in NETWORK_PORTS:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)

def cleanup_iptables(queue_num=1):
    """Remove NFQUEUE iptables rules."""
    for port in NETWORK_PORTS:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)

def handle_nfqueue_packet(packet):
    """Callback for NFQUEUE packets."""
    scapy_pkt = IP(packet.get_payload())
    if TCP in scapy_pkt and scapy_pkt[TCP].dport in NETWORK_PORTS:
        event_json = {
            "id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "type": "network_event",
            "details": {
                "src_ip": scapy_pkt.src,
                "dst_ip": scapy_pkt.dst,
                "sport": scapy_pkt[TCP].sport,
                "dport": scapy_pkt[TCP].dport,
                "protocol": "TCP",
                "action": "connect"
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        send_event(event_json)
        save_event_locally(event_json)

    # Accept packet (could drop/modify if needed)
    packet.accept()

def start_nfqueue_monitor(queue_num=1):
    """Start NFQUEUE monitoring in a background thread."""
    setup_iptables(queue_num)
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, handle_nfqueue_packet)
    
    def run_queue():
        try:
            nfqueue.run()
        finally:
            nfqueue.unbind()
            cleanup_iptables(queue_num)
    
    t = Thread(target=run_queue, daemon=True)
    t.start()
    return t

# === Main ===
if __name__ == "__main__":
    print("Daemon started with Watchdog + NFQUEUE network monitoring.")

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

    # Setup NFQUEUE network monitor
    nfqueue_thread = None
    if config.get("network_monitor", {}).get("enabled", False):
        nfqueue_thread = start_nfqueue_monitor()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Daemon stopped.")
        for obs in observers:
            obs.stop()
            obs.join()
