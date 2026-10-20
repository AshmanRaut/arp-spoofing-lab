# ARP Spoofing Virtual Lab

| Field | Value |
|---|---|
| **Experiment ID** | EXP02 |
| **Experiment Name** | ARP Spoofing |
| **Folder** | `experiments/arp-spoofing/` |
| **Entry File** | `frontend/index.html` |
| **Navigation Title** | ARP Spoofing — Network Attack Demo |
| **Short Description** | An interactive virtual lab that demonstrates ARP Cache Poisoning on an isolated Docker network. Students start three containers (gateway, victim, attacker), trigger a live ARP poisoning attack in MITM or DoS mode, observe the poisoned ARP tables in real time, and apply mitigations — all without touching the host network. |
| **Required Libraries** | None (plain HTML/CSS/JS frontend; Python dependencies are inside Docker images) |
| **Input** | User interactions via browser buttons: Start Lab, Stop Lab, Reset Lab, Start Attack (MITM or DoS mode), Stop Attack, Toggle Mitigation |
| **Output** | Live interactive SVG network topology diagram with animated packet flows (direct IP/ICMP traffic, forged ARP replies, intercepted Layer 2 frames, MITM relays, DoS packet drop zone, and static ARP deflection shields); dynamic node cards with live kernel ARP tables; real-time educational explainer; scrolling activity log; attack/mitigation status badges |
| **Expected Navigation Link** | `/experiments/arp-spoofing/frontend/index.html` |
| **Learning Outcome** | Students will be able to (1) explain how ARP resolves IP-to-MAC addresses and why it lacks authentication, (2) describe how an ARP Cache Poisoning attack redirects traffic, (3) distinguish MITM from DoS outcomes, and (4) evaluate defences including static ARP entries and Dynamic ARP Inspection. |
| **Virtual Lab Components** | 1. **Gateway container** (10.10.10.1) — alpine Linux with IP forwarding, simulates a network router. 2. **Victim container** (10.10.10.10) — alpine + scapy, periodically sends traffic to gateway. 3. **Attacker container** (10.10.10.66) — alpine + scapy, runs `arp_spoof.py` to poison caches on demand. 4. **Backend service** (FastAPI, port 8000) — REST + WebSocket control API; manages containers via Docker SDK. 5. **Frontend** (static HTML/CSS/JS) — live dashboard wired to the backend WebSocket; hosts eight lab sections (Aim, Objective, Theory, Procedure, Simulation, Assignment, References, Feedback). |

---

## Comprehensive Documentation

For an in-depth explanation of the system architecture, OSI Layer 2 / Layer 3 packet mechanics, Scapy poisoning internals, full REST/WebSocket API contracts, and an end-to-end interactive demo walkthrough, please see **[COMPREHENSIVE_GUIDE.md](COMPREHENSIVE_GUIDE.md)**.

---

## How to Run

> **Prerequisites:** Docker Desktop (Windows/macOS) or Docker Engine + Compose plugin (Linux). No other software required.

```bash
# 1. Clone the repository
git clone <repo-url>
cd <repo-name>

# 2. Build and start all containers (first run downloads base images ~150 MB)
docker compose up -d --build

# 3. Open the lab in your browser
#    On Windows: right-click frontend/index.html → Open with → your browser
#    Or navigate directly to:
#      file:///path/to/arp-spoofing-lab/frontend/index.html
#
#    The backend REST API and WebSocket are available at:
#      http://localhost:8000
```

Once the page loads, follow the **Procedure** tab inside the lab for step-by-step instructions.

---

## How to Stop / Reset

```bash
# Stop all containers (images and volumes are preserved)
docker compose stop

# Full reset — stop containers, remove them, remove volumes, rebuild from scratch
docker compose down -v
docker compose up -d --build
```

> **Note:** `docker compose down -v` removes the isolated `arp-lab-net` bridge network and any anonymous volumes. It does **not** delete Docker images, so the next `up --build` only rebuilds layers that changed.

---

## Security Notes

- The `arp-lab-net` network is `internal: true` — containers have **no route** to the host LAN or internet.
- Memory is capped at 256 MB per node (512 MB for the backend) and CPU at 0.5 per node.
- No arbitrary student code runs on the host; all scripts execute inside containers.
