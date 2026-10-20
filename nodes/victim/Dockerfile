FROM alpine:3.20

RUN apk add --no-cache \
        python3 \
        py3-pip \
        iproute2 \
        iputils \
        arping \
        tcpdump \
    && pip3 install --no-cache-dir --break-system-packages scapy

COPY traffic_gen.py /app/traffic_gen.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
