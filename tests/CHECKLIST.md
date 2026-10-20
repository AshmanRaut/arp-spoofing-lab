# Test Checklist — ARP Spoofing Virtual Lab

Use this checklist to verify the lab before submission or evaluation. Each item describes the expected behaviour, how to test it, and what a pass looks like. No automated test runner is required — all checks are manual.

**Tester:** _______________  
**Date:** _______________  
**Machine / OS:** _______________  
**Docker version:** _______________  

Mark each item: **PASS**, **FAIL**, or **SKIP** (with a reason).

---

## 1. Fresh Install — No Manual Dependencies

| # | Check | Expected Result | Status |
|---|---|---|---|
| 1.1 | Clone the repo onto a machine that has **only Docker Desktop installed** (no Python, no scapy, no Node.js) | Clone succeeds | |
| 1.2 | Run `docker compose up -d --build` from the repo root | All 4 services (`gateway`, `victim`, `attacker`, `backend`) reach `running` state; no errors printed | |
| 1.3 | Open `frontend/index.html` in a browser | All 8 tabs render without JavaScript console errors | |
| 1.4 | No files outside the repo directory are created or modified during setup | Verify with `git status` — only the repo files changed | |

---

## 2. Normal Traffic Before Any Attack

| # | Check | Expected Result | Status |
|---|---|---|---|
| 2.1 | Run `docker exec victim ping -c 3 10.10.10.1` | 3 ICMP replies received; packet loss = 0% | |
| 2.2 | Run `docker exec victim ip neigh` | Gateway IP `10.10.10.1` maps to gateway's real MAC (not attacker's `10.10.10.66` MAC) | |
| 2.3 | Run `docker exec gateway ip neigh` | Victim IP `10.10.10.10` maps to victim's real MAC | |
| 2.4 | Click **Start Lab** in the frontend, then check `GET /api/state` response | JSON field `"lab_status"` is `"running"`; ARP tables match real MACs | |
| 2.5 | WebSocket log panel in frontend shows `"type":"log"` messages with `"level":"info"` | No error-level events | |

---

## 3. Attack Reproduces the Expected Poisoned ARP State

| # | Check | Expected Result | Status |
|---|---|---|---|
| 3.1 | Click **Start Attack** → select **MITM** | Backend emits `{"type":"attack_state","active":true,"mode":"mitm"}` event on WebSocket | |
| 3.2 | Within ~5 seconds, check victim's ARP table: `docker exec victim ip neigh` | `10.10.10.1` now resolves to the **attacker's MAC** (`10.10.10.66`'s MAC) | |
| 3.3 | Within ~5 seconds, check gateway's ARP table: `docker exec gateway ip neigh` | `10.10.10.10` now resolves to the **attacker's MAC** | |
| 3.4 | Frontend SVG diagram shows the gateway-arrow in **red** within ~2 seconds of the `arp_update` event | Arrow colour changes to red | |
| 3.5 | `GET /api/state` returns ARP tables reflecting the poisoned state | `"mac"` fields show attacker's MAC for both victim and gateway entries | |
| 3.6 | Click **Stop Attack**, wait 5 seconds, check `docker exec victim ip neigh` again | ARP entries restored to real MACs (stop_poison() sent correct replies) | |
| 3.7 | Click **Start Attack** → select **DoS** | `docker exec victim ping -c 3 10.10.10.1` fails (100% packet loss) while attack is active | |

---

## 4. Mitigation Blocks or Reduces the Attack

| # | Check | Expected Result | Status |
|---|---|---|---|
| 4.1 | With the lab running (no attack active), click **Toggle Mitigation ON** | Backend applies static ARP entries on victim and gateway; emits `{"type":"mitigation_state","enabled":true}` event | |
| 4.2 | Start MITM attack while mitigation is ON | `docker exec victim ip neigh` still shows the **real** gateway MAC (static entry not overwritten) | |
| 4.3 | Frontend status badge changes to **"Running — Protected"** when mitigation is enabled | Badge text and colour update correctly | |
| 4.4 | Click **Toggle Mitigation OFF** | Static ARP entries are removed; ARP poisoning becomes effective again within ~5 seconds | |

---

## 5. Reset Returns to a Clean State

| # | Check | Expected Result | Status |
|---|---|---|---|
| 5.1 | Click **Reset Lab** in the frontend (or run `docker compose down -v && docker compose up -d --build`) | All containers are removed and recreated; no old state persists | |
| 5.2 | After reset, run `docker exec victim ip neigh` | ARP table is clean — no stale attacker entries | |
| 5.3 | `GET /api/state` returns `"attack_active": false` and `"mitigation_enabled": false` | State is reset to initial values | |
| 5.4 | Run `docker compose down -v` and confirm `docker ps -a` shows no lab containers remaining | No zombie containers | |
| 5.5 | Run `docker network ls` after `down -v` | `arp-spoofing-lab_arp-lab-net` network is gone | |

---

## 6. Lab Cannot Reach the Host LAN or Internet

| # | Check | Expected Result | Status |
|---|---|---|---|
| 6.1 | From the victim container, attempt to reach an internet host: `docker exec victim ping -c 3 8.8.8.8` | Request times out; no replies (internal: true network has no external route) | |
| 6.2 | From the attacker container: `docker exec attacker curl -s --max-time 5 https://example.com` | Connection times out or fails; no HTTP response | |
| 6.3 | From the gateway container: `docker exec gateway ping -c 3 1.1.1.1` | Request times out | |
| 6.4 | Inspect the Docker network: `docker network inspect arp-spoofing-lab_arp-lab-net` | `"Internal": true` is present in the JSON output | |

---

## 7. Module Does Not Require Editing Any Other Experiment's Files

| # | Check | Expected Result | Status |
|---|---|---|---|
| 7.1 | All files created by this module are under `experiments/arp-spoofing/` (or the repo root if this is a standalone repo) | No files created/modified outside the repo's own directory tree | |
| 7.2 | No shared configuration files of other experiments (e.g., `main` navigation config, other experiments' `lab.yaml`) were modified | `git diff --name-only` shows only files in this module's folders | |
| 7.3 | The integration team can add this lab to the main navigation by reading `README.md` alone — no verbal explanation needed | README contains all required fields: Experiment ID, Entry File, Navigation Title, Required Libraries, etc. | |

---

## 8. Frontend Standalone Mode (No Backend)

| # | Check | Expected Result | Status |
|---|---|---|---|
| 8.1 | Open `frontend/index.html` directly (file://) with **no backend running** | All 8 tabs load; no crashes; buttons are visible | |
| 8.2 | WebSocket connection failure is handled gracefully | A log message like "WebSocket disconnected" appears in the activity log; the page does not freeze or throw uncaught errors | |
| 8.3 | The **Assignment** tab renders the quiz from `content/quiz.json` | 10 questions display; selecting an answer shows feedback and explanation | |
| 8.4 | The **References** tab renders `content/references.md` | All 6 references appear as readable text | |

---

## Sign-off

After all items above are PASS (or SKIP with valid reason):

- [ ] Module 4 acceptance criteria met: `content/theory.md`, `content/quiz.json`, `content/references.md`, `README.md`, `docs/SETUP.md`, and `tests/CHECKLIST.md` all present and correct.
- [ ] No other team members' files were modified.
- [ ] Ready for PR into `group-EXP-2`.

**Tester signature:** _______________  
**Date completed:** _______________
