from __future__ import annotations

import ipaddress


class IPPoolExhausted(RuntimeError):
    pass


class PeerLimitReached(RuntimeError):
    pass


def allocate_next_ip(
    *,
    network: ipaddress.IPv4Network,
    server_ip: ipaddress.IPv4Address,
    taken: set[str] | set[ipaddress.IPv4Address],
    max_peers: int,
) -> ipaddress.IPv4Address:
    """Return the next free host address inside `network`.

    Uses a 32-bit increment via `IPv4Network.hosts()`, so the allocation
    naturally crosses octet boundaries: the address after 10.0.0.255 inside a
    /22 is 10.0.1.0 (both are valid hosts in 10.0.0.0/22 where only the network
    and broadcast addresses are reserved).

    Raises:
        PeerLimitReached: the configured `max_peers` cap has been hit.
        IPPoolExhausted: every usable address in the subnet is taken.
    """
    if len(taken) >= max_peers:
        raise PeerLimitReached(
            f"peer limit reached: {len(taken)}/{max_peers}"
        )

    taken_addrs: set[ipaddress.IPv4Address] = set()
    for item in taken:
        taken_addrs.add(
            item if isinstance(item, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(item)
        )

    for host in network.hosts():
        if host == server_ip:
            continue
        if host in taken_addrs:
            continue
        return host

    raise IPPoolExhausted(
        f"no free addresses in {network} (taken: {len(taken_addrs)})"
    )
