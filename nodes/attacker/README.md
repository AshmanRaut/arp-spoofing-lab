# Attacker Node — `arp_spoof.py` Control Contract

## Overview

The attacker container runs `arp_spoof.py`, a self-contained Scapy script that sends forged ARP replies to redirect traffic between the victim and the gateway through the attacker node.

The script requires `NET_RAW` and `NET_ADMIN` Linux capabilities (already granted in `docker-compose.yml`) because it opens raw sockets to send ARP packets and writes to `/proc/sys/net/ipv4/ip_forward`.

The backend (Module 2) controls poisoning **exclusively** via `docker exec` against the `attacker` container. It should never exec into `gateway` or `victim` to run attack logic.

---

## Commands the Backend Uses (Module 2 Reference)

### 1. Start ARP Poisoning — MITM Mode
```bash
docker exec attacker python3 arp_spoof.py start --mode mitm
# or
docker exec attacker python3 /arp_spoof.py start --mode mitm
```
- Forks and detaches inside the container, returns immediately (exit code 0, stdout prints `started background poison process, pid=<n>, mode=mitm`).
- Enables IP forwarding inside the attacker container so packets still reach their destinations (Man-in-the-Middle: intercept + relay).
- Sends forged ARP replies every 2 seconds until stopped.

### 2. Start ARP Poisoning — DoS Mode
```bash
docker exec attacker python3 arp_spoof.py start --mode dos
# or
docker exec attacker python3 /arp_spoof.py start --mode dos
```
- Disables IP forwarding — traffic redirected to attacker is silently dropped (Denial of Service).
- Sends forged ARP replies every 2 seconds until stopped.

### 3. Stop ARP Poisoning
```bash
docker exec attacker python3 arp_spoof.py stop
# or
docker exec attacker python3 /arp_spoof.py stop
```
- Sends `SIGTERM` to the running background process.
- The process restores correct ARP replies to both victim and gateway to clean their tables.
- Disables IP forwarding, removes `/tmp/arp_spoof.pid`, and exits cleanly.
- If no attack is running, prints `no poison process is running` and exits 0 (safe to call unconditionally).

### 4. Check Status
```bash
docker exec attacker python3 arp_spoof.py status
```
- Prints exactly `running` or `stopped` on stdout.

---

## Environment Variables (Configured in `docker-compose.yml`)

| Variable     | Default       | Description               |
|--------------|---------------|---------------------------|
| `VICTIM_IP`  | `10.10.10.10` | IP of the victim node     |
| `GATEWAY_IP` | `10.10.10.1`  | IP of the gateway node    |
| `IFACE`      | `eth0`        | Network interface to use  |

---

## Clean-up Guarantee

`docker compose down -v` stops all containers via SIGTERM. The `arp_spoof.py` signal handler catches the termination signal, emits corrective ARP replies to flush poisoned entries, and exits cleanly.
