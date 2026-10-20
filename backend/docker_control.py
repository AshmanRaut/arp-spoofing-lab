"""
docker_control.py
-----------------
Low-level helpers that wrap the Docker Python SDK.

Every public function returns a plain dict (JSON-serialisable) on success and
raises DockerControlError on failure so that app.py can catch it and emit a
{"type":"log","level":"error",...} WebSocket event rather than crashing.
"""

from __future__ import annotations

import re
import time
import subprocess
import os
import logging
from typing import Any

import docker
from docker.errors import DockerException, NotFound, APIError

logger = logging.getLogger(__name__)

# ─── Project-level constants ───────────────────────────────────────────────────
# The backend container is expected to have the project root mounted at
# /workspace (see Dockerfile comments and the top-level docker-compose.yml).
COMPOSE_PROJECT_DIR = os.environ.get("COMPOSE_PROJECT_DIR", "/workspace")
COMPOSE_PROJECT_NAME = os.environ.get("COMPOSE_PROJECT_NAME", "arp-spoofing-lab")

# Container names as defined in docker-compose.yml
CONTAINER_ATTACKER = "attacker"
CONTAINER_VICTIM = "victim"
CONTAINER_GATEWAY = "gateway"

# IPs from lab.yaml / docker-compose.yml
IP_GATEWAY = "10.10.10.1"
IP_VICTIM = "10.10.10.10"
IP_ATTACKER = "10.10.10.66"


class DockerControlError(Exception):
    """Raised when any Docker operation fails."""


def _get_client() -> docker.DockerClient:
    """Return a Docker SDK client connected to the host daemon via the socket."""
    try:
        return docker.from_env()
    except DockerException as exc:
        raise DockerControlError(f"Cannot connect to Docker daemon: {exc}") from exc


# ─── Compose wrappers (use subprocess + docker compose CLI) ───────────────────

def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run `docker compose <args>` in the project directory."""
    cmd = ["docker", "compose", "--project-directory", COMPOSE_PROJECT_DIR,
           "--project-name", COMPOSE_PROJECT_NAME, *args]
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
        )
        return result
    except subprocess.CalledProcessError as exc:
        raise DockerControlError(
            f"docker compose {' '.join(args)} failed:\n"
            f"stdout: {exc.stdout}\nstderr: {exc.stderr}"
        ) from exc
    except FileNotFoundError as exc:
        raise DockerControlError(
            "docker compose not found — is Docker CLI installed in this container?"
        ) from exc


def lab_start() -> dict:
    """docker compose up -d — starts all services in detached mode."""
    _compose("up", "-d", "--build")
    _wait_for_containers([CONTAINER_GATEWAY, CONTAINER_VICTIM, CONTAINER_ATTACKER])
    return {"status": "started"}


def lab_stop() -> dict:
    """docker compose stop — stops all services without removing them."""
    _compose("stop")
    return {"status": "stopped"}


def lab_reset() -> dict:
    """docker compose down -v && docker compose up -d — full teardown + rebuild."""
    _compose("down", "-v", check=False)   # tolerate 'nothing to remove'
    _compose("up", "-d", "--build")
    _wait_for_containers([CONTAINER_GATEWAY, CONTAINER_VICTIM, CONTAINER_ATTACKER])
    return {"status": "reset"}


def _wait_for_containers(names: list[str], timeout: int = 60) -> None:
    """Block until all named containers are in running state (up to *timeout* s)."""
    client = _get_client()
    deadline = time.time() + timeout
    pending = set(names)
    while pending and time.time() < deadline:
        for name in list(pending):
            try:
                c = client.containers.get(name)
                if c.status == "running":
                    pending.discard(name)
            except NotFound:
                pass
        if pending:
            time.sleep(1)
    if pending:
        raise DockerControlError(
            f"Containers still not running after {timeout}s: {pending}"
        )


# ─── Container exec helpers ───────────────────────────────────────────────────

def _exec_in(container_name: str, cmd: list[str]) -> tuple[int, str]:
    """
    Run *cmd* inside the named container via the Docker SDK.
    Returns (exit_code, combined_output).
    """
    client = _get_client()
    try:
        container = client.containers.get(container_name)
    except NotFound as exc:
        raise DockerControlError(f"Container '{container_name}' not found.") from exc

    try:
        exit_code, output = container.exec_run(cmd, demux=False)
        text = output.decode("utf-8", errors="replace") if output else ""
        return exit_code, text
    except APIError as exc:
        raise DockerControlError(
            f"exec_run in '{container_name}' failed: {exc}"
        ) from exc


# ─── Attack control ───────────────────────────────────────────────────────────

def attack_start(mode: str) -> dict:
    """
    docker exec attacker python3 /arp_spoof.py start --mode <mode>
    The script is expected at /arp_spoof.py inside the attacker container.
    """
    if mode not in ("mitm", "dos"):
        raise DockerControlError(f"Invalid mode '{mode}'; must be 'mitm' or 'dos'.")
    exit_code, output = _exec_in(
        CONTAINER_ATTACKER,
        ["python3", "/arp_spoof.py", "start", "--mode", mode],
    )
    if exit_code and exit_code != 0:
        raise DockerControlError(
            f"arp_spoof.py start --mode {mode} exited {exit_code}: {output}"
        )
    return {"status": "attack_started", "mode": mode, "output": output.strip()}


def attack_stop() -> dict:
    """docker exec attacker python3 /arp_spoof.py stop"""
    exit_code, output = _exec_in(
        CONTAINER_ATTACKER,
        ["python3", "/arp_spoof.py", "stop"],
    )
    # tolerate non-zero if the script was already stopped
    return {"status": "attack_stopped", "output": output.strip()}


# ─── Mitigation (static ARP) ──────────────────────────────────────────────────

def _get_mac(container_name: str, iface: str = "eth0") -> str:
    """Read the MAC address of *iface* inside *container_name*."""
    exit_code, output = _exec_in(
        container_name,
        ["cat", f"/sys/class/net/{iface}/address"],
    )
    mac = output.strip()
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac, re.I):
        raise DockerControlError(
            f"Could not read MAC from {container_name}/{iface}: '{mac}'"
        )
    return mac


def mitigation_toggle(enabled: bool) -> dict:
    """
    Add (enabled=True) or remove (enabled=False) static ARP entries so that
    victim → gateway and gateway → victim point at real MACs regardless of
    any poisoning attempt.
    """
    victim_mac = _get_mac(CONTAINER_VICTIM)
    gateway_mac = _get_mac(CONTAINER_GATEWAY)

    if enabled:
        # On victim: pin gateway IP → gateway's real MAC
        _exec_in(CONTAINER_VICTIM,
                 ["arp", "-s", IP_GATEWAY, gateway_mac])
        # On gateway: pin victim IP → victim's real MAC
        _exec_in(CONTAINER_GATEWAY,
                 ["arp", "-s", IP_VICTIM, victim_mac])
        action = "added"
    else:
        # Remove static entries
        _exec_in(CONTAINER_VICTIM,
                 ["arp", "-d", IP_GATEWAY])
        _exec_in(CONTAINER_GATEWAY,
                 ["arp", "-d", IP_VICTIM])
        action = "removed"

    return {
        "status": f"static_arp_{action}",
        "victim_mac": victim_mac,
        "gateway_mac": gateway_mac,
    }


# ─── ARP table parsing ────────────────────────────────────────────────────────

# ip neigh line format (Linux iproute2):
# 10.10.10.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
_IP_NEIGH_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(?P<mac>[0-9a-f:]{17})",
    re.IGNORECASE,
)

# arp -a output format (BusyBox/alpine):
# ? (10.10.10.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
_ARP_A_RE = re.compile(
    r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-f:]{17})",
    re.IGNORECASE,
)


def _parse_arp_table(output: str) -> list[dict]:
    """
    Parse the output of either `ip neigh` or `arp -a` and return a list of
    {"ip": ..., "mac": ...} dicts.
    """
    entries = []
    for line in output.splitlines():
        m = _IP_NEIGH_RE.match(line) or _ARP_A_RE.search(line)
        if m:
            entries.append({"ip": m.group("ip"), "mac": m.group("mac").lower()})
    return entries


def get_arp_table(container_name: str) -> list[dict]:
    """
    Return the ARP table of *container_name* as a list of {"ip":…,"mac":…}.
    Tries `ip neigh` first, falls back to `arp -a`.
    """
    exit_code, output = _exec_in(container_name, ["ip", "neigh"])
    entries = _parse_arp_table(output)
    if not entries:
        # Fallback for minimal images that don't have iproute2
        _, output = _exec_in(container_name, ["arp", "-a"])
        entries = _parse_arp_table(output)
    return entries


# ─── Lab state snapshot ───────────────────────────────────────────────────────

def get_lab_state() -> dict:
    """
    Return a JSON-serialisable dict describing overall lab state:
    - container statuses
    - victim ARP table
    - gateway ARP table
    """
    client = _get_client()
    container_statuses: dict[str, Any] = {}
    for name in (CONTAINER_GATEWAY, CONTAINER_VICTIM, CONTAINER_ATTACKER):
        try:
            c = client.containers.get(name)
            container_statuses[name] = c.status
        except NotFound:
            container_statuses[name] = "not_found"

    victim_arp: list[dict] = []
    gateway_arp: list[dict] = []
    if container_statuses.get(CONTAINER_VICTIM) == "running":
        try:
            victim_arp = get_arp_table(CONTAINER_VICTIM)
        except DockerControlError:
            pass
    if container_statuses.get(CONTAINER_GATEWAY) == "running":
        try:
            gateway_arp = get_arp_table(CONTAINER_GATEWAY)
        except DockerControlError:
            pass

    lab_running = all(
        container_statuses.get(n) == "running"
        for n in (CONTAINER_GATEWAY, CONTAINER_VICTIM, CONTAINER_ATTACKER)
    )

    return {
        "lab_running": lab_running,
        "containers": container_statuses,
        "arp_tables": {
            CONTAINER_VICTIM: victim_arp,
            CONTAINER_GATEWAY: gateway_arp,
        },
    }
