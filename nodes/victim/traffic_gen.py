#!/usr/bin/env python3
"""
Generates periodic, harmless traffic from the victim toward the gateway, so
there is something visible to intercept once the attacker poisons both ARP
caches. This never leaves arp-lab-net.

- one ICMP echo request  (looks like "is my router alive")
- one TCP SYN to port 80 (looks like "an HTTP-like request")
"""
import time

from scapy.all import IP, ICMP, TCP, conf, send

GATEWAY_IP = "10.10.10.1"
IFACE = "eth0"


def main():
    conf.verb = 0
    n = 0
    while True:
        n += 1
        send(IP(dst=GATEWAY_IP) / ICMP(), iface=IFACE)
        send(IP(dst=GATEWAY_IP) / TCP(dport=80, flags="S"), iface=IFACE)
        print(f"[victim] sent probe #{n} to {GATEWAY_IP}", flush=True)
        time.sleep(3)


if __name__ == "__main__":
    main()
