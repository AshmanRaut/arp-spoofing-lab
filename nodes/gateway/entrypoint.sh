#!/bin/sh
set -e

# Namespaced sysctl write — works without --privileged because the
# container has NET_ADMIN.
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

echo "[gateway] ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)"
echo "[gateway] 10.10.10.1 is up on arp-lab-net, idling and answering ARP/ICMP"

tail -f /dev/null
