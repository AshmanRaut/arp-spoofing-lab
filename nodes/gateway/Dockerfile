FROM alpine:3.20

RUN apk add --no-cache \
        python3 \
        py3-pip \
        iproute2 \
        iputils \
        arping \
        tcpdump \
    && pip3 install --no-cache-dir --break-system-packages scapy

RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
