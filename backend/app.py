"""
app.py
------
FastAPI control API for the ARP-Spoofing lab.

REST endpoints  (all at port 8000):
  POST /api/lab/start
  POST /api/lab/stop
  POST /api/lab/reset
  POST /api/attack/start   body: {"mode": "mitm"|"dos"}
  POST /api/attack/stop
  POST /api/mitigation/toggle  body: {"enabled": bool}
  GET  /api/state

WebSocket:
  ws://localhost:8000/ws/logs  — server-push JSON events (see CONTRACT.md)

ARP polling runs every 2 s while the lab is up and emits arp_update events
on any change detected in victim or gateway ARP tables.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import docker_control as dc
from docker_control import DockerControlError

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("arp_lab.api")

# ─── Application state ────────────────────────────────────────────────────────

class AppState:
    lab_running: bool = False
    attack_active: bool = False
    attack_mode: str | None = None
    mitigation_enabled: bool = False
    # Last-seen ARP snapshots per node, used to detect changes
    _arp_cache: dict[str, list[dict]] = {}

app_state = AppState()

# ─── WebSocket connection manager ─────────────────────────────────────────────

class ConnectionManager:
    def __init__(self) -> None:
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.append(ws)
        logger.info("WebSocket client connected. total=%d", len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws) if hasattr(self._clients, "discard") else None
        try:
            self._clients.remove(ws)
        except ValueError:
            pass
        logger.info("WebSocket client disconnected. total=%d", len(self._clients))

    async def broadcast(self, payload: dict) -> None:
        """Send *payload* (as JSON) to every connected client; silently drop dead ones."""
        dead: list[WebSocket] = []
        text = json.dumps(payload)
        for ws in list(self._clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# ─── Event helpers ────────────────────────────────────────────────────────────

def _ts() -> float:
    return time.time()


async def _emit_log(level: Literal["info", "warn", "error"], message: str) -> None:
    await manager.broadcast({"type": "log", "level": level, "message": message, "ts": _ts()})
    log_fn = {"info": logger.info, "warn": logger.warning, "error": logger.error}[level]
    log_fn(message)


async def _emit_attack_state() -> None:
    await manager.broadcast({
        "type": "attack_state",
        "active": app_state.attack_active,
        "mode": app_state.attack_mode,
        "ts": _ts(),
    })


async def _emit_mitigation_state() -> None:
    await manager.broadcast({
        "type": "mitigation_state",
        "enabled": app_state.mitigation_enabled,
        "ts": _ts(),
    })


async def _emit_arp_update(node: str, ip: str, mac: str) -> None:
    await manager.broadcast({
        "type": "arp_update",
        "node": node,
        "ip": ip,
        "mac": mac,
        "ts": _ts(),
    })

# ─── ARP polling background task ─────────────────────────────────────────────

async def _poll_arp_tables() -> None:
    """
    Runs continuously while the app is alive.
    When lab_running=True, polls victim + gateway ARP tables every 2 s and
    broadcasts arp_update events for any changed or new entries.
    """
    POLL_INTERVAL = 2.0
    while True:
        await asyncio.sleep(POLL_INTERVAL)
        if not app_state.lab_running:
            # Reset cache so we get fresh deltas when lab starts again
            app_state._arp_cache = {}
            continue

        for node in (dc.CONTAINER_VICTIM, dc.CONTAINER_GATEWAY):
            try:
                entries = await asyncio.get_event_loop().run_in_executor(
                    None, dc.get_arp_table, node
                )
            except DockerControlError as exc:
                await _emit_log("error", f"ARP poll failed for {node}: {exc}")
                continue

            prev = {e["ip"]: e["mac"] for e in app_state._arp_cache.get(node, [])}
            curr = {e["ip"]: e["mac"] for e in entries}

            for ip, mac in curr.items():
                if prev.get(ip) != mac:
                    await _emit_arp_update(node, ip, mac)

            app_state._arp_cache[node] = entries


# ─── Lifespan (startup / shutdown) ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    task = asyncio.create_task(_poll_arp_tables())
    await _emit_log("info", "ARP Spoofing Lab backend started.")
    yield
    # Shutdown
    task.cancel()


# ─── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="ARP Spoofing Lab — Control API",
    description="Backend for the ARP Spoofing virtual lab. See docs/CONTRACT.md.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # frontend is a static file opened via file://
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Request / response models ────────────────────────────────────────────────

class AttackStartRequest(BaseModel):
    mode: Literal["mitm", "dos"]


class MitigationToggleRequest(BaseModel):
    enabled: bool


# ─── REST endpoints ───────────────────────────────────────────────────────────

@app.post("/api/lab/start", summary="Start the lab (docker compose up -d)")
async def lab_start():
    await _emit_log("info", "Starting lab…")
    try:
        result = await asyncio.get_event_loop().run_in_executor(None, dc.lab_start)
        app_state.lab_running = True
        await _emit_log("info", "Lab started successfully.")
        return result
    except DockerControlError as exc:
        await _emit_log("error", str(exc))
        return {"error": str(exc)}


@app.post("/api/lab/stop", summary="Stop the lab (docker compose stop)")
async def lab_stop():
    await _emit_log("info", "Stopping lab…")
    try:
        result = await asyncio.get_event_loop().run_in_executor(None, dc.lab_stop)
        app_state.lab_running = False
        app_state.attack_active = False
        app_state.attack_mode = None
        app_state.mitigation_enabled = False
        await _emit_log("info", "Lab stopped.")
        await _emit_attack_state()
        await _emit_mitigation_state()
        return result
    except DockerControlError as exc:
        await _emit_log("error", str(exc))
        return {"error": str(exc)}


@app.post("/api/lab/reset", summary="Reset the lab (down -v + up -d)")
async def lab_reset():
    await _emit_log("info", "Resetting lab…")
    try:
        result = await asyncio.get_event_loop().run_in_executor(None, dc.lab_reset)
        app_state.lab_running = True
        app_state.attack_active = False
        app_state.attack_mode = None
        app_state.mitigation_enabled = False
        await _emit_log("info", "Lab reset complete.")
        await _emit_attack_state()
        await _emit_mitigation_state()
        return result
    except DockerControlError as exc:
        await _emit_log("error", str(exc))
        return {"error": str(exc)}


@app.post("/api/attack/start", summary="Start ARP poisoning inside attacker container")
async def attack_start(body: AttackStartRequest):
    if not app_state.lab_running:
        await _emit_log("warn", "Cannot start attack: lab is not running.")
        return {"error": "Lab is not running."}
    await _emit_log("info", f"Starting attack (mode={body.mode})…")
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, dc.attack_start, body.mode
        )
        app_state.attack_active = True
        app_state.attack_mode = body.mode
        await _emit_attack_state()
        await _emit_log("info", f"Attack started in {body.mode} mode.")
        return result
    except DockerControlError as exc:
        await _emit_log("error", str(exc))
        return {"error": str(exc)}


@app.post("/api/attack/stop", summary="Stop ARP poisoning and restore caches")
async def attack_stop():
    await _emit_log("info", "Stopping attack…")
    try:
        result = await asyncio.get_event_loop().run_in_executor(None, dc.attack_stop)
        app_state.attack_active = False
        app_state.attack_mode = None
        await _emit_attack_state()
        await _emit_log("info", "Attack stopped; ARP caches restored.")
        return result
    except DockerControlError as exc:
        await _emit_log("error", str(exc))
        return {"error": str(exc)}


@app.post("/api/mitigation/toggle", summary="Add/remove static ARP entries on victim+gateway")
async def mitigation_toggle(body: MitigationToggleRequest):
    if not app_state.lab_running:
        await _emit_log("warn", "Cannot toggle mitigation: lab is not running.")
        return {"error": "Lab is not running."}
    action = "Enabling" if body.enabled else "Disabling"
    await _emit_log("info", f"{action} ARP mitigation…")
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, dc.mitigation_toggle, body.enabled
        )
        app_state.mitigation_enabled = body.enabled
        await _emit_mitigation_state()
        await _emit_log("info", f"Mitigation {'enabled' if body.enabled else 'disabled'}.")
        return result
    except DockerControlError as exc:
        await _emit_log("error", str(exc))
        return {"error": str(exc)}


@app.get("/api/state", summary="Current lab status + ARP tables")
async def get_state():
    try:
        snapshot = await asyncio.get_event_loop().run_in_executor(None, dc.get_lab_state)
        return {
            **snapshot,
            "attack_active": app_state.attack_active,
            "attack_mode": app_state.attack_mode,
            "mitigation_enabled": app_state.mitigation_enabled,
        }
    except DockerControlError as exc:
        await _emit_log("error", str(exc))
        return {"error": str(exc)}


# ─── WebSocket endpoint ───────────────────────────────────────────────────────

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await manager.connect(websocket)
    # Send a welcome / current-state snapshot so a late-joining client is
    # immediately up to date without waiting for the next poll cycle.
    await websocket.send_text(json.dumps({
        "type": "log",
        "level": "info",
        "message": "Connected to ARP Lab WebSocket.",
        "ts": _ts(),
    }))
    await websocket.send_text(json.dumps({
        "type": "attack_state",
        "active": app_state.attack_active,
        "mode": app_state.attack_mode,
        "ts": _ts(),
    }))
    await websocket.send_text(json.dumps({
        "type": "mitigation_state",
        "enabled": app_state.mitigation_enabled,
        "ts": _ts(),
    }))
    try:
        while True:
            # Keep the connection alive; we only push, never pull.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
