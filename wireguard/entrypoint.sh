#!/bin/sh
# Bring up wg0 without any wg0.conf. Peers are managed at runtime by the bot
# via `docker exec ... wg set wg0 peer ...`.
set -eu

: "${WG_INTERFACE:=wg0}"
: "${WG_SERVER_PORT:=51820}"
: "${WG_SERVER_IP:=10.0.0.1}"
: "${WG_NETWORK:=10.0.0.0/22}"
: "${WG_EGRESS_IFACE:=eth0}"

KEY_DIR="/run/wg"
PRIV_KEY="${KEY_DIR}/server.key"
PUB_KEY="${KEY_DIR}/server.pub"

mkdir -p "${KEY_DIR}"
chmod 700 "${KEY_DIR}"

if [ ! -s "${PRIV_KEY}" ]; then
    echo "[wg] generating server private key at ${PRIV_KEY}"
    umask 077
    wg genkey > "${PRIV_KEY}"
fi

# Always (re)derive the public key so the bot can read it from the shared volume.
wg pubkey < "${PRIV_KEY}" > "${PUB_KEY}"
chmod 644 "${PUB_KEY}"

WG_PREFIX="$(echo "${WG_NETWORK}" | cut -d/ -f2)"
WG_CIDR="${WG_SERVER_IP}/${WG_PREFIX}"

echo "[wg] starting interface ${WG_INTERFACE} on ${WG_CIDR}, listen ${WG_SERVER_PORT}/udp"

ip link add "${WG_INTERFACE}" type wireguard
wg set "${WG_INTERFACE}" listen-port "${WG_SERVER_PORT}" private-key "${PRIV_KEY}"
ip addr add "${WG_CIDR}" dev "${WG_INTERFACE}"
ip link set "${WG_INTERFACE}" up

# Equivalent of PostUp from the user's wg0.conf.
iptables -A FORWARD -i "${WG_INTERFACE}" -j ACCEPT
iptables -A FORWARD -o "${WG_INTERFACE}" -j ACCEPT
iptables -t nat -A POSTROUTING -o "${WG_EGRESS_IFACE}" -j MASQUERADE

cleanup() {
    echo "[wg] shutting down ${WG_INTERFACE}"
    iptables -D FORWARD -i "${WG_INTERFACE}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "${WG_INTERFACE}" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "${WG_EGRESS_IFACE}" -j MASQUERADE 2>/dev/null || true
    ip link del "${WG_INTERFACE}" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "[wg] ready; server pubkey: $(cat "${PUB_KEY}")"

# Block forever; tini forwards signals to this process so `cleanup` runs.
tail -f /dev/null &
wait $!
