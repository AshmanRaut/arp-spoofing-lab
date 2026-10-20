# Attacker node — `arp_spoof.py` control contract

The backend (Module 2) controls poisoning **exclusively** via `docker exec`
against the `attacker` container. It should never exec into `gateway` or
`victim` to run attack logic.

## Start an attack

```bash
docker exec attacker python3 arp_spoof.py start --mode mitm
docker exec attacker python3 arp_spoof.py start --mode dos
```

- Forks and detaches inside the container, returns immediately (exit code 0,
  stdout prints `started background poison process, pid=<n>, mode=<mode>`).
- `--mode` defaults to `mitm` if omitted.
- Calling `start` a second time while one is already running exits non-zero
  with `a poison process already appears to be running (pid file exists)` —
  the backend should call `stop` first, or check `status`.

## Stop an attack

```bash
docker exec attacker python3 arp_spoof.py stop
```

Sends `SIGTERM` to the background poisoning process. That process then:
1. disables IP forwarding,
2. sends correct ARP replies to both victim and gateway to restore their
   real tables,
3. removes its own pid file, then exits.

If nothing is running, this prints `no poison process is running` and exits
0 (safe to call unconditionally).

## Check status

```bash
docker exec attacker python3 arp_spoof.py status
```

Prints exactly `running` or `stopped` on stdout — easy to parse.

## Reading the ARP tables (for `GET /api/state`)

The backend reads current ARP state directly from victim/gateway, e.g.:

```bash
docker exec victim  ip neigh show
docker exec gateway ip neigh show
```

or with `net-tools`-style output from the attacker node itself:

```bash
docker exec attacker arp -a
```

## Notes for Module 2

- Default victim/gateway IPs are `10.10.10.10` / `10.10.10.1`, overridable
  per-call with `--victim` / `--gateway`, or by setting `VICTIM_IP` /
  `GATEWAY_IP` env vars on the `attacker` service.
- Logs are written both to stdout and to `/tmp/arp_spoof.log` inside the
  container — tail with `docker exec attacker tail -f /tmp/arp_spoof.log`.
- Only one poison process runs at a time (enforced via a pid file at
  `/tmp/arp_spoof.pid`).
- `docker compose down -v` removes the container entirely, so no cleanup of
  pid/log files is needed between runs.
