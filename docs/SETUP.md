# Setup Guide — ARP Spoofing Virtual Lab

This guide walks you through installing Docker, cloning the repository, and running the lab on **Windows**, **macOS**, and **Linux**. No programming experience is required.

---

## Step 1 — Install Docker

### Windows

1. Go to <https://www.docker.com/products/docker-desktop/> and download **Docker Desktop for Windows**.
2. Run the installer. When prompted, keep the default option: **Use WSL 2 instead of Hyper-V** (recommended). If WSL 2 is not already installed, the installer will guide you through it.
3. After installation, **restart your computer**.
4. Open Docker Desktop from the Start menu. Wait until the whale icon in the taskbar shows **"Docker Desktop is running"**.
5. Open **PowerShell** or **Command Prompt** and verify:
   ```
   docker --version
   docker compose version
   ```
   Both commands should print version numbers.

### macOS

1. Go to <https://www.docker.com/products/docker-desktop/> and download **Docker Desktop for Mac** (choose Apple Silicon or Intel depending on your chip).
2. Open the `.dmg` file and drag Docker to your Applications folder.
3. Launch Docker from Applications. Accept the service agreement. Wait for the menu-bar whale icon to show a green dot.
4. Open **Terminal** and verify:
   ```
   docker --version
   docker compose version
   ```

### Linux (Ubuntu / Debian)

```bash
# Remove any old Docker versions
sudo apt-get remove docker docker-engine docker.io containerd runc

# Install prerequisites
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key and repository
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and Compose plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Allow your user to run Docker without sudo (log out and back in after this)
sudo usermod -aG docker $USER

# Verify
docker --version
docker compose version
```

---

## Step 2 — Clone the Repository

Open a terminal (PowerShell on Windows, Terminal on macOS/Linux) and run:

```bash
git clone <repo-url>
cd arp-spoofing-lab
```

Replace `<repo-url>` with the URL provided by your team or instructor.

---

## Step 3 — Build and Start the Lab

```bash
# 1. Build and start all 4 containers in detached mode
docker compose up -d --build

# 2. Confirm all 4 containers are up and running
docker compose ps
```

You should see all 4 services in the `Up` state:
```text
NAME       IMAGE                       COMMAND                  STATUS
attacker   arp-spoofing-lab-attacker   "/entrypoint.sh"         Up
backend    arp-spoofing-lab-backend    "uvicorn app:app ..."    Up (port 8000)
gateway    arp-spoofing-lab-gateway    "/entrypoint.sh"         Up
victim     arp-spoofing-lab-victim     "/entrypoint.sh"         Up
```

What this does:
- **`--build`** rebuilds Docker images from the local Dockerfiles (required on first run or after any code change).
- **`-d`** runs everything in the background (detached mode).
- On first run, Docker downloads the base Alpine/Python images (~100–150 MB total). Subsequent starts are faster.

### Opening the Frontend

Once the containers are running, open `frontend/index.html` in your web browser:

- **macOS Terminal:**
  ```bash
  open frontend/index.html
  ```
- **Linux Terminal:**
  ```bash
  xdg-open frontend/index.html
  ```
- **Windows (PowerShell):**
  ```powershell
  start frontend\index.html
  ```
- **Graphical File Explorer:** Double-click `frontend/index.html` or drag it into any modern web browser (Chrome, Firefox, Safari, Edge). No local web server or build tool is needed.

---

## Step 4 — Using the Lab

Inside the browser page, follow the **Procedure** tab. The basic flow is:

1. Click **Start Lab** — starts the three containers (`gateway`, `victim`, `attacker`).
2. Observe normal traffic: Animated traveling packet dots (green ICMP Request / cyan Reply) flow directly between the Victim and Gateway cards.
3. Select an attack mode (**MITM** or **DoS**) from the dropdown and click **Start Attack**.
4. Observe the live animated topology map:
   - Forged ARP reply injection curves stream red packets from the Attacker into Victim and Gateway.
   - Outbound frames from the Victim are physically redirected along an amber path to the Attacker (`① Intercepted Frame`).
   - In **MITM mode**, a purple path shows the Attacker relaying frames to the Gateway (`② Relayed to Gateway`).
   - In **DoS mode**, frames are dropped into a red blackhole zone (`② BLACKHOLE`).
   - The Victim and Gateway node cards pulse red and update their ARP tables to show `⚠️ POISONED!`.
5. Toggle **Mitigation enabled** to ON — static ARP entries lock the kernel neighbor tables, blue deflection shields (`🛡️ Static ARP Blocked`) appear, and direct legitimate communication is restored.
6. Click **Stop Attack**, then **Stop Lab** when finished.

---

## Step 5 — Stop or Reset the Lab

```bash
# Temporarily pause containers (preserves state and images)
docker compose stop

# Resume paused containers
docker compose up -d

# Full reset — removes containers, volumes, and the isolated network
docker compose down -v
```

To start from a completely clean state after a reset:

```bash
docker compose up -d --build
```

---

## Troubleshooting — The 3 Most Likely Errors

### Error 1: Docker is not running

**Symptom:** Running `docker compose up` produces:
```
error during connect: ... Is the docker daemon running?
```

**Fix:**
- **Windows/macOS:** Open Docker Desktop and wait for the status to say "Running" (green whale icon).
- **Linux:** Start the daemon with `sudo systemctl start docker` (or `sudo service docker start`). If you just added yourself to the `docker` group, log out and back in.

---

### Error 2: Port 8000 is already in use

**Symptom:** Running `docker compose up` produces:
```
Error response from daemon: Ports are not available: exposing port TCP 0.0.0.0:8000 -> 0.0.0.0:0: listen tcp 0.0.0.0:8000: bind: address already in use
```

**Fix — find and stop whatever is using port 8000:**

**Windows (PowerShell):**
```powershell
netstat -ano | findstr ":8000"
# Note the PID in the last column, then:
taskkill /PID <PID> /F
```

**macOS / Linux:**
```bash
lsof -i :8000
# Note the PID, then:
kill -9 <PID>
```

Alternatively, change the port mapping in `docker-compose.yml` from `"8000:8000"` to `"8001:8000"` and update the backend URL in `frontend/script.js` accordingly.

---

### Error 3: Antivirus or firewall blocks the isolated Docker network

**Symptom:** `docker compose up` succeeds, but containers cannot communicate with each other. The simulation shows no ARP activity even after clicking Start Lab.

**Fix:**
- **Windows Defender / Windows Firewall:** Open Windows Defender Firewall → Advanced Settings → Inbound Rules → ensure Docker Desktop's rules are allowed. Docker Desktop usually configures these automatically, but some corporate policies block virtual network adapters.
- **Third-party antivirus (Avast, Kaspersky, etc.):** Temporarily disable "Network Shield" or "Packet Filter" features, restart Docker Desktop, then try again.
- **Corporate VPN:** Some VPN clients (especially split-tunnel VPNs) conflict with Docker's virtual networks. Disconnect from the VPN, restart Docker Desktop, and run the lab.
- **General check:** Run `docker network ls` — you should see a network named `arp-spoofing-lab_arp-lab-net`. If it is missing, run `docker compose down -v && docker compose up -d --build`.

---

### Error 4: WebSocket shows "connecting" or "disconnected"

**Symptom:** In the top header of `frontend/index.html`, the status dot remains yellow ("connecting") or turns red ("disconnected"). Live logs and ARP updates do not stream in.

**Fix:**
- Confirm the backend container is running:
  ```bash
  docker compose ps
  ```
  Ensure `backend` is listed as `Up`.
- Check the backend logs for any startup crashes or port errors:
  ```bash
  docker logs backend --tail 50
  ```
- Test if the backend REST API responds directly in your terminal:
  ```bash
  curl http://localhost:8000/api/state
  ```
- If accessing from a remote VM, WSL 2 host IP, or non-standard port, configure `window.LAB_API_BASE_URL` inside `frontend/index.html` or update the port binding in `docker-compose.yml`.

---

## Verifying the Lab Works (Quick Sanity Check)

After `docker compose up -d --build`, you can run these checks without opening the browser:

```bash
# Confirm all 4 containers are running
docker compose ps

# Test victim can reach gateway (before any attack)
docker exec victim ping -c 3 10.10.10.1

# Check victim's ARP table (should show gateway's real MAC)
docker exec victim ip neigh

# Check the backend API is responsive
curl http://localhost:8000/api/state
```

If `ping` succeeds and `curl` returns JSON, the lab is working correctly.
