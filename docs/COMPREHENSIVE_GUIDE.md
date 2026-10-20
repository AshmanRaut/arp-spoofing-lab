# Comprehensive Guide — ARP Spoofing Virtual Lab

> **Experiment ID:** EXP02  
> **Experiment Name:** ARP Spoofing & Cache Poisoning Virtual Lab  
> **Course:** Computer Security / Network Security  
> **Distribution Model:** Containerized micro-lab (`docker compose up -d` → open `frontend/index.html`)

---

## 1. Executive Summary & Project Purpose

The **ARP Spoofing Virtual Lab** is an interactive, browser-based cybersecurity teaching laboratory designed to demonstrate how the **Address Resolution Protocol (ARP)** works at OSI Layer 2, why its lack of authentication leaves networks vulnerable to **ARP Cache Poisoning**, and how security controls (such as **Static ARP entries** and **Dynamic ARP Inspection**) mitigate the threat.

### Key Highlights:
- **100% Isolated:** All attack and legitimate traffic is contained within an internal Docker bridge network (`internal: true`) with no routing to the host LAN or internet.
- **Zero Host Dependencies:** Runs on plain Docker Desktop. No Python, Scapy, Node.js, or compiler toolchains are required on the host.
- **Real Packet Manipulation:** Unlike mock simulators that animate pre-rendered slides, this lab executes **real raw-socket Scapy scripts** inside Linux containers that inject real Ethernet/ARP frames and alter kernel ARP tables in real time.
- **Live Visual Dashboard:** A pure HTML5/CSS3/JavaScript frontend connects to the backend over WebSocket and REST, rendering an SVG network topology that turns red the exact second a container's ARP cache is poisoned.

---

## 2. High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Host Machine (Browser)                           │
│                                                                             │
│   frontend/index.html (HTML5, Vanilla CSS3, ES2020 JavaScript)              │
│   ├── Interactive SVG Topology Diagram (live arrow color updates)           │
│   ├── Live Controls (Start/Stop Lab, MITM/DoS Attack, Mitigation Toggle)    │
│   ├── Real-time Activity Log (WebSocket Event Stream)                       │
│   └── Educational Tabs (Aim, Objective, Theory, Procedure, Quiz, Citations) │
└───────────────────────▲─────────────────────────────┬───────────────────────┘
                        │ WebSocket (/ws/logs)         │ REST (port 8000)
                        │ push events                  │ HTTP POST / GET
┌───────────────────────┴─────────────────────────────▼───────────────────────┐
│                     Backend Control API (FastAPI Container)                 │
│                                                                             │
│   backend/app.py & backend/docker_control.py                                │
│   ├── Talks to host Docker daemon via mounted /var/run/docker.sock          │
│   ├── Background ARP Poller: Inspects node ARP tables every 2 seconds       │
│   └── Event Broadcaster: Emits arp_update, attack_state, mitigation_state   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Docker SDK (exec_run, compose CLI)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              Isolated Docker Bridge Network ("arp-lab-net", 10.10.10.0/24)  │
│                                                                             │
│   ┌─────────────────────┐    Legitimate ICMP/HTTP   ┌─────────────────────┐ │
│   │  Victim Container   │◄─────────────────────────►│  Gateway Container  │ │
│   │     10.10.10.10     │                           │     10.10.10.1      │ │
│   │ (Traffic Generator) │                           │   (Default Router)  │ │
│   └──────────▲──────────┘                           └──────────▲──────────┘ │
│              │                                                 │            │
│              │ Forged ARP Replies: "10.10.10.1 is at attacker" │            │
│              │ Forged ARP Replies: "10.10.10.10 is at attacker"│            │
│              ▼                                                 ▼            │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │                      Attacker Container (10.10.10.66)                 │ │
│   │  nodes/attacker/arp_spoof.py (Scapy Engine)                           │ │
│   │  - MITM Mode: Enables IP forwarding (intercepts & relays frames)      │ │
│   │  - DoS Mode: Disables IP forwarding (blackholes traffic)              │ │
│   │  - Stop: Emits corrective ARP replies to restore caches               │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. How Everything Works Under the Hood

### 3.1 Network Layer (`arp-lab-net`)
- Defined in `docker-compose.yml` with `internal: true`. Docker installs kernel firewall rules that prevent packets on this bridge from being NAT'ed or routed out to the physical host network or public internet.
- Subnet is fixed to `10.10.10.0/24`. The Docker bridge gateway sits at `10.10.10.254`, freeing `10.10.10.1` for our custom `gateway` router container.

### 3.2 The Node Containers
1. **Gateway (`10.10.10.1`)**:
   - Alpine Linux router with kernel `net.ipv4.ip_forward=1`.
   - Answers ICMP echo requests and simulated web traffic from the subnet.
2. **Victim (`10.10.10.10`)**:
   - Runs `traffic_gen.py` in the background, sending periodic ICMP pings and TCP SYN probes to `10.10.10.1` every 3 seconds to generate realistic traffic for interception.
3. **Attacker (`10.10.10.66`)**:
   - Contains `arp_spoof.py` with `NET_RAW` and `NET_ADMIN` Linux capabilities.
   - Controllable via `docker exec` without requiring shell access on the host.

### 3.3 Attack Engine (`arp_spoof.py`)
- **Discovery**: Upon starting, it sends genuine ARP requests to learn the genuine MAC addresses of both the victim and gateway so it knows what to restore later.
- **Poisoning Loop**: Every 2 seconds, it sends forged ARP replies (`op=2`):
  - To `10.10.10.10` claiming `10.10.10.1` is at the attacker's MAC.
  - To `10.10.10.1` claiming `10.10.10.10` is at the attacker's MAC.
- **MITM Mode vs. DoS Mode**:
  - In **MITM mode**, it sets `/proc/sys/net/ipv4/ip_forward = 1`. Packets redirected to the attacker are inspected and forwarded to their real destination, maintaining connectivity while eavesdropping.
  - In **DoS mode**, it sets `ip_forward = 0`. Traffic redirected to the attacker is silently discarded, causing 100% packet loss for the victim.
- **Restoration**: Upon receiving `SIGTERM` (when clicking Stop Attack), the script emits 3 corrective ARP replies with genuine Layer 2 (`Ether.src`) and Layer 3 (`ARP.hwsrc`) addresses, flushing the forged entries from both machines' caches.

### 3.4 Mitigation Mechanism (Static ARP)
- When mitigation is enabled, the backend executes `arp -s <ip> <mac>` on both the victim and gateway.
- This creates `PERMANENT` neighbor entries in the Linux kernel ARP tables. The kernel ignores subsequent forged dynamic ARP replies, shielding the nodes from poisoning.

### 3.5 Backend Control Service (`backend/app.py`)
- Built with **FastAPI** and the **Docker Python SDK**.
- Mounts `/var/run/docker.sock` so it can start, stop, exec into, and inspect container status.
- Scoped to only manipulate `gateway`, `victim`, and `attacker`, ensuring the backend control API remains alive during lab stops and resets.
- Contains an asynchronous 2-second background poller that queries `ip neigh` on victim and gateway. When an entry changes or a new client connects, an `arp_update` JSON event is streamed over WebSocket.

### 3.6 Frontend User Interface (`frontend/`)
- Single-page application built with vanilla HTML5, CSS3, and ES2020 JavaScript.
- Fully compatible with `file://` protocol; no web server or build tool required.
- Dynamically queries `/api/state` on launch to learn the real MAC addresses assigned by Docker on the host machine.
- **Interactive Live Topology & Animated Packet Flow**: Visualizes real packet mechanics in real time with animated SVG flows (direct ICMP/TCP packets in teal/cyan, red forged ARP injection streams, amber intercepted Layer 2 frames diverted to the attacker, and purple MITM relayed frames to the gateway). Detailed node cards render live kernel ARP caches, while deflection shields activate when static ARP mitigation protects the network.

---

## 4. Repository Structure

```
arp-spoofing-lab/
├── COMPREHENSIVE_GUIDE.md           ← Complete architectural, mechanics & API reference guide
├── README.md                        ← Integration team metadata & project summary
├── lab.yaml                         ← Institutional virtual lab manifest
├── docker-compose.yml               ← 4-service topology & isolated network definition
├── docs/
│   ├── CONTRACT.md                  ← Shared REST + WebSocket communication contract
│   └── SETUP.md                     ← Complete guide for Docker install, execution & troubleshooting
├── nodes/                           ← Container definitions for network nodes
│   ├── gateway/
│   │   ├── Dockerfile               ← Alpine router with IP forwarding enabled
│   │   └── entrypoint.sh            ← Idles and answers ARP/ICMP requests
│   ├── victim/
│   │   ├── Dockerfile               ← Alpine victim target machine
│   │   ├── entrypoint.sh            ← Starts background traffic generator
│   │   └── traffic_gen.py           ← Scapy periodic ICMP/TCP probe generator
│   └── attacker/
│       ├── Dockerfile               ← Alpine attacker machine with Scapy
│       ├── arp_spoof.py             ← Real Scapy ARP poisoning & restoration daemon
│       ├── entrypoint.sh            ← Container startup script
│       └── README.md                ← CLI control contract for docker exec commands
├── backend/                         ← FastAPI control API service
│   ├── app.py                       ← FastAPI application, WebSocket hub & ARP poller
│   ├── docker_control.py            ← Docker SDK container & Compose manager
│   ├── requirements.txt             ← Python dependencies (FastAPI, uvicorn, docker)
│   └── Dockerfile                   ← Python 3.11-slim container with Docker CLI
├── frontend/                        ← Static browser user interface (Zero build step)
│   ├── index.html                   ← HTML5 layout with 8 pedagogical tabs
│   ├── style.css                    ← Responsive design system & customizable theme tokens
│   └── script.js                    ← SVG diagram renderer, WebSocket client & quiz engine
├── content/                         ← Academic & curriculum deliverables
│   ├── theory.md                    ← Detailed protocol theory & defense mechanics
│   ├── quiz.json                    ← 10 multiple-choice assessment questions
│   └── references.md                ← Academic & RFC citations
└── tests/
    └── CHECKLIST.md                 ← 32-point verification checklist (All PASS)
```

---

## 5. API & WebSocket Contract

### 5.1 REST Endpoints (Port 8000)

| Method | Endpoint | Request Body | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/lab/start` | *None* | Starts the 3 node containers (`gateway`, `victim`, `attacker`) |
| `POST` | `/api/lab/stop` | *None* | Stops the 3 node containers without killing the backend |
| `POST` | `/api/lab/reset` | *None* | Destroys node state and recreates clean containers |
| `POST` | `/api/attack/start` | `{"mode": "mitm" \| "dos"}` | Launches `arp_spoof.py` in attacker container |
| `POST` | `/api/attack/stop` | *None* | Sends SIGTERM to restore authentic ARP tables |
| `POST` | `/api/mitigation/toggle` | `{"enabled": true \| false}` | Configures permanent static ARP entries on nodes |
| `GET` | `/api/state` | *None* | Returns container status, real MACs, and ARP tables |

#### Example State Response (`GET /api/state`):
```json
{
  "lab_status": "running",
  "lab_running": true,
  "containers": {
    "gateway": "running",
    "victim": "running",
    "attacker": "running"
  },
  "real_macs": {
    "gateway": "0a:2b:6a:55:16:2e",
    "victim": "8a:e9:32:9e:6b:ef",
    "attacker": "92:c3:09:82:08:1e"
  },
  "arp_tables": {
    "victim": [
      { "ip": "10.10.10.1", "mac": "0a:2b:6a:55:16:2e" },
      { "ip": "10.10.10.66", "mac": "92:c3:09:82:08:1e" }
    ],
    "gateway": [
      { "ip": "10.10.10.10", "mac": "8a:e9:32:9e:6b:ef" },
      { "ip": "10.10.10.66", "mac": "92:c3:09:82:08:1e" }
    ]
  },
  "attack_active": false,
  "attack_mode": null,
  "mitigation_enabled": false
}
```

### 5.2 WebSocket Stream (`ws://localhost:8000/ws/logs`)

The backend broadcasts real-time JSON events to all connected clients:

```json
{"type": "arp_update", "node": "victim", "ip": "10.10.10.1", "mac": "92:c3:09:82:08:1e", "ts": 1729443500}
{"type": "attack_state", "active": true, "mode": "mitm", "ts": 1729443500}
{"type": "mitigation_state", "enabled": true, "ts": 1729443500}
{"type": "log", "level": "info", "message": "Attack started in mitm mode.", "ts": 1729443500}
```

---

## 6. Lab Setup & Execution Guide

All step-by-step instructions for installing Docker, starting the containers, opening the browser dashboard, stopping/resetting the environment, and troubleshooting common issues are maintained in the dedicated setup guide:

👉 **[docs/SETUP.md](docs/SETUP.md)**

Please consult `docs/SETUP.md` for:
- Docker installation procedures for Windows (WSL 2), macOS, and Linux
- Starting all 4 lab containers with Docker Compose (`docker compose up -d --build`)
- Expected container status verification (`docker compose ps`)
- Cross-platform commands to launch `frontend/index.html` (macOS, Linux, Windows)
- Commands for pausing (`docker compose stop`), resuming (`docker compose up -d`), and full teardown (`docker compose down -v`)
- Troubleshooting port 8000 conflicts, isolated network firewall issues, and WebSocket connectivity

---

## 7. Step-by-Step Demonstration Walkthrough

Once `frontend/index.html` opens in your browser:

1. **Verify Connection**:
   - In the top-right header, confirm the WebSocket status dot is green (**`connected`**) and the lab status badge shows **`Running — Vulnerable`**.
2. **Review Normal Communication**:
   - On the **Simulation** tab, inspect the Live ARP Network Map.
   - The direct horizontal link between **Victim Target** and **Default Gateway** is solid vibrant **teal** and shows traveling animated packet dots (green ICMP Echo Request / cyan ICMP Echo Reply).
   - Both node cards display authentic physical NIC MACs and genuine kernel ARP bindings (`✓ Authentic Gateway` and `✓ Authentic Victim`).
   - The sidebar displays **Controls** and **Activity Log** right at the top without any redundant tab duplicates.
3. **Execute MITM Attack**:
   - Set the attack dropdown to **`MITM`** and click **Start Attack**.
   - Within 2 seconds:
     - The direct link is severed (`Direct Path Severed (Traffic Diverted)`).
     - Two red curves fire animated forged ARP reply bursts from the Attacker into Victim and Gateway (`⚡ Forged ARP: 10.10.10.1=Attacker`).
     - An amber animated curve shows outbound frames from Victim being intercepted by the Attacker (`① Intercepted Frame (Dst MAC = Attacker)`).
     - A purple animated curve shows the Attacker relaying frames to the Gateway (`② Relayed to Gateway (ip_forward=1)`).
     - Both Victim and Gateway node cards pulse red and update their live ARP caches to **`⚠️ POISONED!`**.
     - The topology card header badge switches to **`MITM Attack: Intercepting & Relaying`**, and the bottom explainer banner provides a live explanation of Layer 2 redirection.
4. **Inspect Inside the Container (Optional)**:
   In your terminal, run:
   ```bash
   docker exec victim ip neigh
   ```
   You will see `10.10.10.1` now resolves to the attacker's MAC address!
5. **Enable Mitigation (Defense)**:
   - Toggle the switch **`Mitigation enabled`** to ON.
   - Static ARP entries are pinned in the Linux kernel (`PERMANENT`).
   - Blue deflection shields (**`🛡️ Static ARP Blocked`**) appear on both Victim and Gateway, deflecting the forged replies.
   - The direct communication link between Victim and Gateway is restored and protected.
   - The status badge updates to **`Protected (Static ARP)`**.
6. **Stop Attack & Clean Up**:
   - Click **Stop Attack**.
   - The authentic gateway MAC is restored, forged packet streams stop, and the diagram returns to normal.
7. **Take the Assignment Quiz**:
   - Click on the **Assignment** tab.
   - Complete the 10 interactive multiple-choice questions with instant feedback and score tracking.
