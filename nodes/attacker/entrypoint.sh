#!/bin/sh
set -e

echo "[attacker] 10.10.10.66 is up on arp-lab-net"
echo "[attacker] control it with:"
echo "  docker exec attacker python3 arp_spoof.py start --mode mitm"
echo "  docker exec attacker python3 arp_spoof.py start --mode dos"
echo "  docker exec attacker python3 arp_spoof.py stop"
echo "  docker exec attacker python3 arp_spoof.py status"

tail -f /dev/null
