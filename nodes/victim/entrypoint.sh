#!/bin/sh
set -e

echo "[victim] 10.10.10.10 is up on arp-lab-net"
echo "[victim] starting background traffic generator (logs to stdout)"
python3 /app/traffic_gen.py &

tail -f /dev/null
