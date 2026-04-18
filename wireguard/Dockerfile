FROM alpine:3.20

RUN apk add --no-cache \
        wireguard-tools \
        iptables \
        ip6tables \
        iproute2 \
        bash \
        tini

COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh \
    && chmod +x /entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
