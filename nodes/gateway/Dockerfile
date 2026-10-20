FROM alpine:3.20

# Gateway node: acts as router / default gateway (10.10.10.1).
# Needs:
#   - iproute2:  `ip neigh` ARP table inspection
#   - net-tools: `arp -a`, `arp -s`, `arp -d` for static ARP mitigation
#   - iputils:   ping
#   - arping:    ARP resolution and probing
#   - tcpdump:   passive capture
RUN apk add --no-cache \
        python3 \
        py3-pip \
        iproute2 \
        net-tools \
        arping \
        tcpdump \
    && pip3 install --no-cache-dir --break-system-packages scapy

# Enable IP forwarding at kernel level
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
