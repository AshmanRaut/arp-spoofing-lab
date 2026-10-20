FROM alpine:3.19

# Install tools needed by victim node:
#   - python3/scapy: optional traffic generation script
#   - iproute2:      `ip neigh` for ARP table inspection
#   - net-tools:     `arp -a` fallback
#   - arping/ping:   ICMP traffic to gateway
#   - tcpdump:       passive packet capture for demo purposes
RUN apk add --no-cache \
        python3 \
        py3-pip \
        iproute2 \
        net-tools \
        arping \
        iputils \
        tcpdump \
    && pip3 install --no-cache-dir scapy

# A simple traffic generator: pings the gateway every 5 s
COPY traffic.py /traffic.py

CMD ["python3", "/traffic.py"]
