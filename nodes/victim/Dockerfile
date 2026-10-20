FROM alpine:3.20

# Install tools needed by victim node (10.10.10.10):
#   - python3/scapy: traffic generation script (traffic_gen.py)
#   - iproute2:      `ip neigh` for ARP table inspection
#   - net-tools:     `arp -a`, `arp -s`, `arp -d` for static ARP mitigation
#   - arping/iputils:ping and ICMP traffic
#   - tcpdump:       passive packet capture
RUN apk add --no-cache \
        python3 \
        py3-pip \
        iproute2 \
        net-tools \
        arping \
        tcpdump \
    && pip3 install --no-cache-dir --break-system-packages scapy

COPY traffic_gen.py /app/traffic_gen.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/traffic_gen.py

WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
