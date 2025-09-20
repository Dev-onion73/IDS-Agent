#!/usr/bin/env python3
import os
import json
import uuid
from datetime import datetime
import yaml
from client import send_event
from bcc import BPF
import socket
import struct

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

# === Local storage function ===
def save_event_locally(event_json):
    filename = FILE_EVENTS_JSON if event_json["type"] == "file_event" else NETWORK_EVENTS_JSON
    with open(filename, "a") as f:
        f.write(json.dumps(event_json) + "\n")

# === Helper to convert IP int to dotted string ===
def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("<I", addr))

# === Load eBPF programs ===
file_bpf = BPF(src_file="ebpf/file_monitor.c")
network_bpf = BPF(src_file="ebpf/network_monitor.c")

# Attach kprobes
file_bpf.attach_kprobe(event="sys_openat", fn_name="trace_openat")
network_bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")

# === Callback functions ===
def handle_file_event(cpu, data, size):
    event = file_bpf["events"].event(data)
    file_path = event.filename.decode(errors="ignore")

    # Filter based on configured paths
    if FILE_PATHS and not any(file_path.startswith(p) for p in FILE_PATHS):
        return  # Skip unmonitored paths

    event_json = {
        "id": str(uuid.uuid4()),
        "device_id": DEVICE_ID,
        "type": "file_event",
        "details": {
            "pid": event.pid,
            "uid": event.uid,
            "process": event.comm.decode(errors="ignore"),
            "path": file_path,
            "action": "open"
        },
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    send_event(event_json)
    save_event_locally(event_json)

def handle_network_event(cpu, data, size):
    event = network_bpf["events"].event(data)
    dport = event.dport

    # Filter based on configured ports
    if NETWORK_PORTS and dport not in NETWORK_PORTS:
        return  # Skip unmonitored ports

    event_json = {
        "id": str(uuid.uuid4()),
        "device_id": DEVICE_ID,
        "type": "network_event",
        "details": {
            "pid": event.pid,
            "uid": event.uid,
            "process": event.comm.decode(errors="ignore"),
            "src_ip": int_to_ip(event.saddr),
            "dst_ip": int_to_ip(event.daddr),
            "dport": dport,
            "protocol": "TCP",
            "action": "connect"
        },
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    send_event(event_json)
    save_event_locally(event_json)

# === Open perf buffers ===
file_bpf["events"].open_perf_buffer(handle_file_event)
network_bpf["events"].open_perf_buffer(handle_network_event)

# === Main loop ===
if __name__ == "__main__":
    print("Daemon started with eBPF monitoring.")
    try:
        while True:
            file_bpf.perf_buffer_poll()
            network_bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Daemon stopped.")
