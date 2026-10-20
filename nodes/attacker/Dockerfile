FROM alpine:3.20

# Install tools needed by attacker node:
# python3, scapy, iproute2, net-tools (for arp -a), arping, tcpdump
RUN apk add --no-cache \
        python3 \
        py3-pip \
        iproute2 \
        net-tools \
        arping \
        tcpdump \
    && pip3 install --no-cache-dir --break-system-packages scapy

# Copy the ARP spoof script to both /app and filesystem root for easy access
COPY arp_spoof.py /app/arp_spoof.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/arp_spoof.py && \
    ln -sf /app/arp_spoof.py /arp_spoof.py

WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
