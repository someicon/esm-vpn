from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Peer, User


async def get_or_create_user(
    session: AsyncSession,
    *,
    telegram_id: int,
    username: str | None,
) -> User:
    stmt = select(User).where(User.telegram_id == telegram_id)
    user = (await session.execute(stmt)).scalar_one_or_none()
    if user is None:
        user = User(telegram_id=telegram_id, username=username)
        session.add(user)
        await session.flush()
    elif user.username != username:
        user.username = username
        await session.flush()
    return user


async def get_user_by_telegram_id(
    session: AsyncSession, telegram_id: int
) -> User | None:
    stmt = select(User).where(User.telegram_id == telegram_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_peers_for_user(session: AsyncSession, user_id: int) -> list[Peer]:
    stmt = select(Peer).where(Peer.user_id == user_id).order_by(Peer.id)
    return list((await session.execute(stmt)).scalars().all())


async def get_peer_by_name(
    session: AsyncSession, user_id: int, name: str
) -> Peer | None:
    stmt = select(Peer).where(Peer.user_id == user_id, Peer.name == name)
    return (await session.execute(stmt)).scalar_one_or_none()


async def all_assigned_ips(session: AsyncSession) -> set[str]:
    stmt = select(Peer.assigned_ip)
    return {row for row in (await session.execute(stmt)).scalars().all()}


async def all_peers(session: AsyncSession) -> list[Peer]:
    stmt = select(Peer).order_by(Peer.id)
    return list((await session.execute(stmt)).scalars().all())


async def create_peer(
    session: AsyncSession,
    *,
    user_id: int,
    name: str,
    public_key: str,
    assigned_ip: str,
) -> Peer:
    peer = Peer(
        user_id=user_id,
        name=name,
        public_key=public_key,
        assigned_ip=assigned_ip,
    )
    session.add(peer)
    await session.flush()
    return peer


async def delete_peer(session: AsyncSession, peer: Peer) -> None:
    await session.delete(peer)
    await session.flush()


async def update_peer_handshakes(
    session: AsyncSession,
    updates: dict[str, datetime],
) -> None:
    """Persist the latest known handshake time for peers, keyed by public key.

    Only moves `last_handshake_at` forward — an older kernel value (e.g. right
    after a wireguard container restart, where the counter resets to 0) never
    overwrites a newer stored value.
    """
    if not updates:
        return
    stmt = select(Peer).where(Peer.public_key.in_(updates.keys()))
    peers = list((await session.execute(stmt)).scalars().all())
    for peer in peers:
        new_ts = updates[peer.public_key]
        if peer.last_handshake_at is None or new_ts > peer.last_handshake_at:
            peer.last_handshake_at = new_ts
    await session.flush()
