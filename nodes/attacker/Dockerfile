FROM alpine:3.19

# Install Python 3, net-tools (arp command), iproute2 (ip neigh), arping, tcpdump
RUN apk add --no-cache \
        python3 \
        py3-pip \
        iproute2 \
        net-tools \
        arping \
        tcpdump \
        iputils

# Copy the ARP spoof script to the filesystem root for easy `docker exec` usage
COPY arp_spoof.py /arp_spoof.py
RUN chmod +x /arp_spoof.py

# Enable NET_ADMIN + NET_RAW capabilities (granted in docker-compose.yml)
# The script needs:
#   - AF_PACKET/SOCK_RAW  → NET_RAW
#   - /proc/sys/net/ipv4/ip_forward write → NET_ADMIN

CMD ["sh", "-c", "sleep infinity"]
