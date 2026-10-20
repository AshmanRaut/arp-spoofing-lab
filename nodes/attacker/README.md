# Attacker Node — ARP Spoofing Script

## Overview

The attacker container runs `arp_spoof.py`, a self-contained Python 3 script
that sends forged ARP replies to redirect traffic between the victim and the
gateway through the attacker node.

The script requires `NET_RAW` and `NET_ADMIN` Linux capabilities (already
granted in `docker-compose.yml`) because it opens a raw socket and writes to
`/proc/sys/net/ipv4/ip_forward`.

---

## Commands the backend uses (Module 2 reference)

### Start ARP poisoning — MITM mode
```bash
docker exec attacker python3 /arp_spoof.py start --mode mitm
```
- Enables IP forwarding inside the attacker container so packets still reach
  their destinations (Man-in-the-Middle: intercept + forward).
- Sends forged ARP replies every 2 s until stopped.

### Start ARP poisoning — DoS mode
```bash
docker exec attacker python3 /arp_spoof.py start --mode dos
```
- Disables IP forwarding — traffic redirected to attacker is silently dropped
  (Denial of Service).

### Stop ARP poisoning
```bash
docker exec attacker python3 /arp_spoof.py stop
```
- Writes a sentinel file and sends SIGTERM to the running start process.
- The start process sends corrective ARP replies to restore victim/gateway
  caches before exiting.

---

## Environment variables (override defaults in docker-compose.yml)

| Variable     | Default       | Description               |
|--------------|---------------|---------------------------|
| `VICTIM_IP`  | `10.10.10.10` | IP of the victim node     |
| `GATEWAY_IP` | `10.10.10.1`  | IP of the gateway node    |
| `IFACE`      | `eth0`        | Network interface to use  |

---

## How it works (no scapy required)

1. Reads the attacker's own MAC from `/sys/class/net/eth0/address`.
2. Looks up victim and gateway MACs from `/proc/net/arp` (populated after the
   first ICMP ping in the lab startup sequence).
3. Constructs raw Ethernet + ARP frames (ARP Reply, OPER=2) and sends them
   with a `AF_PACKET / SOCK_RAW` socket bound to `eth0`.
4. Sends:
   - To victim: "gateway IP is at attacker's MAC"
   - To gateway: "victim IP is at attacker's MAC"
5. Repeats every 2 s (interval configurable via `POISON_INTERVAL` constant).

On stop, sends corrective replies with the real MACs to flush poisoned entries.

---

## Clean-up guarantee

`docker compose down -v` stops all containers via SIGTERM → the `start`
loop's signal handler fires → corrective ARP replies → clean exit.
