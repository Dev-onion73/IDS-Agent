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
from threading import Thread

from pyroute2 import IPRoute, IPDB, NetlinkError
from pyroute2.netlink.rtnl import RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR
from pyroute2.netlink import NLMSG_DONE

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

# === Netlink-based Network Monitoring ===
def netlink_monitor():
    """Monitor TCP connection events via Netlink (conntrack events can be used with NFNETLINK_CONNTRACK)."""
    from pyroute2 import NFNetlinkConntrack

    ct = NFNetlinkConntrack()
    ct.bind(groups=ct.CTNLGRP_CONNTRACK_NEW | ct.CTNLGRP_CONNTRACK_UPDATE)
    
    try:
        for msg in ct:
            # Only track TCP connections
            try:
                attrs = dict(msg.get('attrs', []))
                protoinfo = attrs.get('CTA_PROTOINFO')
                if not protoinfo:
                    continue
                sport = protoinfo.get('sport')
                dport = protoinfo.get('dport')
                if NETWORK_PORTS and dport not in NETWORK_PORTS:
                    continue

                event_json = {
                    "id": str(uuid.uuid4()),
                    "device_id": DEVICE_ID,
                    "type": "network_event",
                    "details": {
                        "src_ip": attrs.get('CTA_SRC_IPV4') or attrs.get('CTA_SRC_IPV6'),
                        "dst_ip": attrs.get('CTA_DST_IPV4') or attrs.get('CTA_DST_IPV6'),
                        "sport": sport,
                        "dport": dport,
                        "protocol": "TCP",
                        "action": msg.get('event')  # 'new', 'update', 'destroy'
                    },
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                send_event(event_json)
                save_event_locally(event_json)
            except Exception as e:
                continue
    finally:
        ct.close()

# === Main ===
if __name__ == "__main__":
    print("Daemon started with Watchdog + Netlink network monitoring.")

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

    # Start Netlink network monitor in a background thread
    netlink_thread = None
    if config.get("network_monitor", {}).get("enabled", False):
        netlink_thread = Thread(target=netlink_monitor, daemon=True)
        netlink_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Daemon stopped.")
        for obs in observers:
            obs.stop()
            obs.join()
