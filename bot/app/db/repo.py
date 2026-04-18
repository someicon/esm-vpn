from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Peer, PeerTrafficDaily, User


def as_utc(dt: datetime | None) -> datetime | None:
    """Promote a DB-read naive datetime to a UTC-aware one.

    SQLite has no native tz support, so SQLAlchemy returns naive datetimes
    even when the column is declared `DateTime(timezone=True)`. We always
    store UTC, so attaching tzinfo on read is safe.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


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


async def get_peer_by_pubkey(
    session: AsyncSession, public_key: str
) -> Peer | None:
    stmt = select(Peer).where(Peer.public_key == public_key)
    return (await session.execute(stmt)).scalar_one_or_none()


async def apply_traffic_delta(
    session: AsyncSession,
    peer: Peer,
    rx_delta: int,
    tx_delta: int,
    day: date,
) -> None:
    """Bump lifetime totals and the daily bucket for (peer, day).

    Callers are expected to have already computed a non-negative delta
    (handling counter resets). Zero deltas are a no-op.
    """
    if rx_delta <= 0 and tx_delta <= 0:
        return
    rx_delta = max(rx_delta, 0)
    tx_delta = max(tx_delta, 0)

    peer.rx_total = (peer.rx_total or 0) + rx_delta
    peer.tx_total = (peer.tx_total or 0) + tx_delta

    stmt = select(PeerTrafficDaily).where(
        PeerTrafficDaily.peer_id == peer.id,
        PeerTrafficDaily.day == day,
    )
    bucket = (await session.execute(stmt)).scalar_one_or_none()
    if bucket is None:
        bucket = PeerTrafficDaily(
            peer_id=peer.id, day=day, rx_bytes=rx_delta, tx_bytes=tx_delta
        )
        session.add(bucket)
    else:
        bucket.rx_bytes = (bucket.rx_bytes or 0) + rx_delta
        bucket.tx_bytes = (bucket.tx_bytes or 0) + tx_delta


async def traffic_last_days(
    session: AsyncSession, peer_id: int, days: int
) -> tuple[int, int]:
    """Return (rx, tx) sum over the last `days` calendar days (UTC)."""
    since = datetime.now(tz=timezone.utc).date() - timedelta(days=days - 1)
    stmt = select(
        func.coalesce(func.sum(PeerTrafficDaily.rx_bytes), 0),
        func.coalesce(func.sum(PeerTrafficDaily.tx_bytes), 0),
    ).where(
        PeerTrafficDaily.peer_id == peer_id,
        PeerTrafficDaily.day >= since,
    )
    row = (await session.execute(stmt)).one()
    return int(row[0]), int(row[1])


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
        stored = as_utc(peer.last_handshake_at)
        if stored is None or new_ts > stored:
            peer.last_handshake_at = new_ts
    await session.flush()
