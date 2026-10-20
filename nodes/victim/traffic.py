#!/usr/bin/env python3
"""
traffic.py — Victim traffic generator.

Sends an ICMP ping to the gateway every 5 seconds so that:
  1. The victim's ARP cache stays populated with the gateway's MAC.
  2. There is visible traffic for the attacker to intercept / drop.

This runs as the default CMD of the victim container.
"""

import subprocess
import time
import os

GATEWAY_IP = os.environ.get("GATEWAY_IP", "10.10.10.1")
INTERVAL = 5  # seconds

print(f"[victim] Traffic generator starting. Target: {GATEWAY_IP}", flush=True)

while True:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", GATEWAY_IP],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"[victim] ping {GATEWAY_IP} OK", flush=True)
        else:
            print(f"[victim] ping {GATEWAY_IP} FAILED (possibly poisoned/DoS)", flush=True)
    except Exception as exc:
        print(f"[victim] ping error: {exc}", flush=True)
    time.sleep(INTERVAL)
