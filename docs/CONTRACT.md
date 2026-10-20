# Shared Contract

All 4 modules must agree on this. Copy this section verbatim into `docs/CONTRACT.md` as the repo's first commit (see Section 0).

**REST (backend, port 8000):**

| Method | Path | Body | Purpose |
| --- | --- | --- | --- |
| POST | `/api/lab/start` | — | Build + start all 3 containers |
| POST | `/api/lab/stop` | — | Stop containers, keep images |
| POST | `/api/lab/reset` | — | Stop, remove, rebuild clean state |
| POST | `/api/attack/start` | `{"mode":"mitm"\|"dos"}` | Run ARP poison script in attacker container |
| POST | `/api/attack/stop` | — | Restore correct ARP mappings |
| POST | `/api/mitigation/toggle` | `{"enabled": true\|false}` | Apply static ARP entries on victim/gateway |
| GET | `/api/state` | — | Current lab status + both ARP tables |

**WebSocket** `ws://localhost:8000/ws/logs` — backend pushes JSON events, frontend only renders them:

```json
{"type":"arp_update","node":"victim","ip":"10.10.10.1","mac":"<claimed-mac>","ts":169...}
{"type":"packet","from":"victim","to":"gateway","via":"attacker","encrypted":false,"ts":169...}
{"type":"attack_state","active":true,"mode":"mitm","ts":169...}
{"type":"mitigation_state","enabled":true,"ts":169...}
{"type":"log","level":"info","message":"...","ts":169...}
```

Everyone builds against this contract from day one; nobody waits for someone else's code to exist.
