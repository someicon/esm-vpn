from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Iterable

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container

from app.config import get_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PeerStatus:
    public_key: str
    endpoint: str | None
    allowed_ips: str
    latest_handshake: int  # unix ts, 0 = never
    rx_bytes: int
    tx_bytes: int
    keepalive: str | None


class WireGuardError(RuntimeError):
    pass


class WireGuardService:
    """Manages WireGuard peers inside the sibling container via `docker exec`.

    The bot never writes a wg0.conf. All peer state lives in kernel WG session
    plus the bot's own database; `reconcile()` re-applies the DB state onto the
    running interface after a container restart.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._container_name = settings.wg_container_name
        self._interface = settings.wg_interface
        self._client = docker.from_env()

    # ---------- low-level ----------

    def _container(self) -> Container:
        try:
            return self._client.containers.get(self._container_name)
        except NotFound as exc:
            raise WireGuardError(
                f"wireguard container '{self._container_name}' not found"
            ) from exc

    def _exec_sync(self, cmd: list[str]) -> str:
        try:
            container = self._container()
            result = container.exec_run(cmd, demux=False, tty=False)
        except APIError as exc:
            raise WireGuardError(f"docker exec failed: {exc}") from exc

        output = result.output or b""
        text = output.decode("utf-8", errors="replace")
        if result.exit_code != 0:
            raise WireGuardError(
                f"wg command failed ({result.exit_code}): "
                f"{' '.join(cmd)} -> {text.strip()}"
            )
        return text

    async def _exec(self, cmd: list[str]) -> str:
        return await asyncio.to_thread(self._exec_sync, cmd)

    # ---------- public API ----------

    async def add_peer(
        self,
        *,
        public_key: str,
        allowed_ip: str,
    ) -> None:
        cmd = [
            "wg", "set", self._interface,
            "peer", public_key,
            "allowed-ips", f"{allowed_ip}/32",
        ]
        await self._exec(cmd)

    async def remove_peer(self, public_key: str) -> None:
        cmd = [
            "wg", "set", self._interface,
            "peer", public_key, "remove",
        ]
        await self._exec(cmd)

    async def list_peers(self) -> list[PeerStatus]:
        """Parse `wg show <iface> dump`.

        The first line describes the interface itself; subsequent lines are
        peers with columns:
        public_key, preshared_key, endpoint, allowed_ips, latest_handshake,
        rx, tx, persistent_keepalive.
        """
        output = await self._exec(["wg", "show", self._interface, "dump"])
        lines = [ln for ln in output.splitlines() if ln.strip()]
        peers: list[PeerStatus] = []
        for line in lines[1:]:
            cols = line.split("\t")
            if len(cols) < 8:
                continue
            endpoint = cols[2] if cols[2] != "(none)" else None
            keepalive = cols[7] if cols[7] not in ("off", "(none)") else None
            peers.append(
                PeerStatus(
                    public_key=cols[0],
                    endpoint=endpoint,
                    allowed_ips=cols[3],
                    latest_handshake=int(cols[4] or 0),
                    rx_bytes=int(cols[5] or 0),
                    tx_bytes=int(cols[6] or 0),
                    keepalive=keepalive,
                )
            )
        return peers

    async def server_public_key(self) -> str:
        """Read the server pubkey directly off the running interface."""
        output = await self._exec(["wg", "show", self._interface, "public-key"])
        return output.strip()

    async def reconcile(
        self,
        desired: Iterable[tuple[str, str]],
    ) -> None:
        """Ensure every (public_key, allowed_ip) in `desired` is configured.

        Peers already present with a matching allowed-ip are left alone.
        Peers present but with a different IP are re-added (wg set overrides).
        Unknown peers (in the runtime but not in the DB) are removed.
        """
        desired_map = {pk: ip for pk, ip in desired}
        try:
            current = {p.public_key: p for p in await self.list_peers()}
        except WireGuardError as exc:
            logger.warning("reconcile: cannot read current peers: %s", exc)
            return

        for pk, ip in desired_map.items():
            expected_allowed = f"{ip}/32"
            present = current.get(pk)
            if present is not None and present.allowed_ips == expected_allowed:
                continue
            try:
                await self.add_peer(public_key=pk, allowed_ip=ip)
                logger.info("reconcile: added/updated peer %s -> %s", pk[:8], ip)
            except WireGuardError as exc:
                logger.error("reconcile: failed to add %s: %s", pk[:8], exc)

        for pk in current.keys() - desired_map.keys():
            try:
                await self.remove_peer(pk)
                logger.info("reconcile: removed stale peer %s", pk[:8])
            except WireGuardError as exc:
                logger.error("reconcile: failed to remove %s: %s", pk[:8], exc)
