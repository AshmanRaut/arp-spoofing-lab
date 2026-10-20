FROM alpine:3.19

# Gateway node: acts as a router / default gateway.
# Needs:
#   - iproute2:  `ip neigh` ARP table inspection
#   - net-tools: `arp -a` fallback
#   - iptables:  optional packet mangling
#   - iputils:   ping
#   - tcpdump:   passive capture
RUN apk add --no-cache \
        iproute2 \
        net-tools \
        iptables \
        iputils \
        tcpdump

# Enable IP forwarding at kernel level (also set per-container by docker-compose.yml sysctls)
RUN echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# Simple keepalive entrypoint — gateway just needs to be reachable
CMD ["sh", "-c", "echo 'Gateway running'; sleep infinity"]
