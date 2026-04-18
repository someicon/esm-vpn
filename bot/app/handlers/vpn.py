from __future__ import annotations

import logging
from datetime import datetime, timezone

from aiogram import Router
from aiogram.filters import Command, CommandObject
from aiogram.types import BufferedInputFile, Message
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import repo
from app.services.config_builder import build_client_config
from app.services.ip_alloc import (
    IPPoolExhausted,
    PeerLimitReached,
    allocate_next_ip,
)
from app.services.keys import generate_keypair
from app.services.wg import WireGuardError, WireGuardService

logger = logging.getLogger(__name__)

router = Router(name="vpn")

NAME_MAX_LEN = 32


def _sanitize_name(raw: str) -> str | None:
    name = raw.strip()
    if not name or len(name) > NAME_MAX_LEN:
        return None
    if not all(c.isalnum() or c in "-_" for c in name):
        return None
    return name


def _format_bytes(n: int) -> str:
    if n <= 0:
        return "0 B"
    if n < 1024:
        return f"{n} B"
    x = float(n)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        x /= 1024
        if x < 1024:
            return f"{x:.2f} {unit}"
    return f"{x:.2f} PiB"


def _format_handshake(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    delta = datetime.now(tz=timezone.utc) - dt
    seconds = int(delta.total_seconds())
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


@router.message(Command("new"))
async def on_new(
    message: Message,
    command: CommandObject,
    session: AsyncSession,
    wg: WireGuardService,
) -> None:
    if message.from_user is None:
        return
    if not command.args:
        await message.answer("Usage: /new <name> (letters, digits, '-', '_'; up to 32 chars)")
        return
    name = _sanitize_name(command.args)
    if name is None:
        await message.answer("Invalid name. Use letters, digits, '-', '_' (max 32 chars).")
        return

    settings = get_settings()

    user = await repo.get_or_create_user(
        session,
        telegram_id=message.from_user.id,
        username=message.from_user.username,
    )

    if await repo.get_peer_by_name(session, user.id, name) is not None:
        await message.answer(f"A peer named '{name}' already exists.")
        return

    taken = await repo.all_assigned_ips(session)
    try:
        ip_addr = allocate_next_ip(
            network=settings.wg_network,
            server_ip=settings.wg_server_ip,
            taken=taken,
            max_peers=settings.wg_max_peers,
        )
    except PeerLimitReached:
        await message.answer(
            f"Global peer limit reached ({settings.wg_max_peers}). "
            "Delete unused peers and try again."
        )
        return
    except IPPoolExhausted:
        await message.answer("No free IP addresses left in the pool.")
        return

    keypair = await generate_keypair()

    try:
        await wg.add_peer(public_key=keypair.public_key, allowed_ip=str(ip_addr))
    except WireGuardError as exc:
        logger.exception("wg add_peer failed")
        await message.answer(f"Failed to add peer on the VPN server: {exc}")
        return

    # Everything after this point must either succeed, or roll back the WG peer
    # so kernel state and DB state stay in sync. DbSessionMiddleware will roll
    # back the DB session on its own when we re-raise.
    try:
        await repo.create_peer(
            session,
            user_id=user.id,
            name=name,
            public_key=keypair.public_key,
            assigned_ip=str(ip_addr),
        )

        try:
            server_pub = await wg.server_public_key()
        except WireGuardError as exc:
            logger.warning("cannot fetch server pubkey from interface: %s", exc)
            server_pub = ""
            try:
                server_pub = settings.wg_server_pubkey_path.read_text().strip()
            except OSError:
                pass

        if not server_pub:
            raise WireGuardError("server public key is unavailable")

        config = build_client_config(
            client_private_key=keypair.private_key,
            client_ip=ip_addr,
            dns=settings.wg_dns,
            server_public_key=server_pub,
            server_endpoint=settings.wg_server_endpoint,
            peer_name=name,
        )

        await message.answer_document(
            BufferedInputFile(config.text.encode("utf-8"), filename=config.filename),
            caption=(
                f"Peer '{name}' created.\n"
                f"IP: {ip_addr}\n"
                "The private key is NOT stored on the server; keep this file safe."
            ),
        )
        await message.answer_photo(
            BufferedInputFile(config.qr_png_bytes(), filename=f"{name}.png"),
            caption="Scan this QR from the WireGuard mobile app to import the config.",
        )
    except Exception:
        logger.exception("peer creation failed after wg add; rolling back")
        try:
            await wg.remove_peer(keypair.public_key)
        except WireGuardError:
            logger.exception("failed to rollback wg peer after handler error")
        try:
            await message.answer(
                "Peer creation failed; the change was rolled back. Please try again."
            )
        except Exception:
            logger.exception("failed to notify user about rollback")
        raise


@router.message(Command("list"))
async def on_list(
    message: Message,
    session: AsyncSession,
    wg: WireGuardService,
) -> None:
    if message.from_user is None:
        return
    user = await repo.get_user_by_telegram_id(session, message.from_user.id)
    if user is None:
        peers = []
    else:
        peers = await repo.list_peers_for_user(session, user.id)

    if not peers:
        await message.answer("You have no peers yet. Create one with /new <name>.")
        return

    try:
        runtime = {p.public_key: p for p in await wg.list_peers()}
    except WireGuardError as exc:
        logger.warning("list: wg show failed: %s", exc)
        runtime = {}

    # Persist any fresh handshake times so they survive wg container restarts.
    updates: dict[str, datetime] = {
        pk: datetime.fromtimestamp(status.latest_handshake, tz=timezone.utc)
        for pk, status in runtime.items()
        if status.latest_handshake > 0
    }
    if updates:
        await repo.update_peer_handshakes(session, updates)

    lines = ["Your peers:"]
    for peer in peers:
        status = runtime.get(peer.public_key)
        runtime_dt: datetime | None = None
        if status and status.latest_handshake > 0:
            runtime_dt = datetime.fromtimestamp(
                status.latest_handshake, tz=timezone.utc
            )
        # Use whichever is newest: live runtime value or the persisted one
        # (persisted one matters after a wireguard container restart).
        stored_dt = repo.as_utc(peer.last_handshake_at)
        candidates = [d for d in (runtime_dt, stored_dt) if d is not None]
        last = max(candidates) if candidates else None

        rx_30, tx_30 = await repo.traffic_last_days(session, peer.id, days=30)
        total_30 = rx_30 + tx_30
        total_all = (peer.rx_total or 0) + (peer.tx_total or 0)

        lines.append(
            f"• {peer.name} ({peer.assigned_ip})\n"
            f"   handshake: {_format_handshake(last)}\n"
            f"   30d: {_format_bytes(total_30)}  ·  all-time: {_format_bytes(total_all)}"
        )
    await message.answer("\n".join(lines))


@router.message(Command("delete"))
async def on_delete(
    message: Message,
    command: CommandObject,
    session: AsyncSession,
    wg: WireGuardService,
) -> None:
    if message.from_user is None:
        return
    if not command.args:
        await message.answer("Usage: /delete <name>")
        return
    name = _sanitize_name(command.args)
    if name is None:
        await message.answer("Invalid name.")
        return

    user = await repo.get_user_by_telegram_id(session, message.from_user.id)
    if user is None:
        await message.answer(f"No peer '{name}' found.")
        return

    peer = await repo.get_peer_by_name(session, user.id, name)
    if peer is None:
        await message.answer(f"No peer '{name}' found.")
        return

    try:
        await wg.remove_peer(peer.public_key)
    except WireGuardError as exc:
        logger.warning("wg remove failed for %s: %s", peer.public_key[:8], exc)

    await repo.delete_peer(session, peer)
    await message.answer(f"Peer '{name}' deleted.")
