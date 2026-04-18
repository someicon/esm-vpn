from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime, timezone

from aiogram import Bot, Dispatcher
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import get_settings
from app.db import repo
from app.db.session import get_session_factory, init_db
from app.handlers import build_router
from app.middlewares.auth import AdminOnlyMiddleware
from app.middlewares.db import DbSessionMiddleware
from app.services.wg import WireGuardError, WireGuardService

logger = logging.getLogger(__name__)

RUNTIME_SYNC_INTERVAL_S = 60


async def _reconcile_on_startup(wg: WireGuardService) -> None:
    session_factory = get_session_factory()
    async with session_factory() as session:
        peers = await repo.all_peers(session)
    desired = [(p.public_key, p.assigned_ip) for p in peers]
    if not desired:
        logger.info("startup: no peers in DB, nothing to reconcile")
        return
    logger.info("startup: reconciling %d peer(s) with running WG", len(desired))
    try:
        await wg.reconcile(desired)
    except WireGuardError as exc:
        logger.error("reconcile failed: %s", exc)


async def _runtime_sync_loop(
    wg: WireGuardService,
    session_factory: async_sessionmaker[AsyncSession],
    interval_s: int = RUNTIME_SYNC_INTERVAL_S,
) -> None:
    """Periodically snapshot runtime peer state (handshake + traffic) into the DB.

    Runs forever until cancelled. WG errors are swallowed with a log — if the
    wireguard container is temporarily down, we just wait for the next tick.

    Traffic accounting: we compute `current - last_seen` per peer. If the
    current kernel counter is lower than what we saw last (kernel reset after
    a WG container restart), we treat `current` itself as the delta — that
    way we never double-count and never lose bytes accrued in the new epoch.
    """
    while True:
        try:
            runtime_peers = await wg.list_peers()
        except WireGuardError as exc:
            logger.warning("sync: wg unavailable: %s", exc)
            runtime_peers = []
        except Exception:
            logger.exception("sync: unexpected error, backing off")
            runtime_peers = []

        if runtime_peers:
            try:
                async with session_factory() as session:
                    today = datetime.now(tz=timezone.utc).date()
                    for rp in runtime_peers:
                        peer = await repo.get_peer_by_pubkey(session, rp.public_key)
                        if peer is None:
                            continue

                        if rp.latest_handshake > 0:
                            new_ts = datetime.fromtimestamp(
                                rp.latest_handshake, tz=timezone.utc
                            )
                            stored = repo.as_utc(peer.last_handshake_at)
                            if stored is None or new_ts > stored:
                                peer.last_handshake_at = new_ts

                        rx_last = peer.rx_last_seen or 0
                        tx_last = peer.tx_last_seen or 0
                        rx_delta = (
                            rp.rx_bytes if rp.rx_bytes < rx_last
                            else rp.rx_bytes - rx_last
                        )
                        tx_delta = (
                            rp.tx_bytes if rp.tx_bytes < tx_last
                            else rp.tx_bytes - tx_last
                        )
                        if rx_delta or tx_delta:
                            await repo.apply_traffic_delta(
                                session, peer, rx_delta, tx_delta, today
                            )
                        peer.rx_last_seen = rp.rx_bytes
                        peer.tx_last_seen = rp.tx_bytes

                    await session.commit()
            except Exception:
                logger.exception("sync: DB write failed")

        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            logger.info("sync: cancelled, exiting")
            raise


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    settings = get_settings()

    await init_db()

    bot = Bot(token=settings.bot_token)
    dp = Dispatcher()

    wg = WireGuardService()

    # Best-effort reconcile; don't block bot startup on WG availability.
    try:
        await asyncio.wait_for(_reconcile_on_startup(wg), timeout=10)
    except asyncio.TimeoutError:
        logger.warning("reconcile timed out, continuing startup")
    except Exception:
        logger.exception("reconcile crashed, continuing startup")

    dp.update.middleware(DbSessionMiddleware(get_session_factory()))
    dp.update.middleware(AdminOnlyMiddleware(settings.admin_ids))

    dp.include_router(build_router())

    sync_task = asyncio.create_task(
        _runtime_sync_loop(wg, get_session_factory()),
        name="runtime-sync",
    )

    logger.info("bot starting (polling)")
    try:
        await dp.start_polling(bot, wg=wg)
    finally:
        sync_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sync_task


if __name__ == "__main__":
    asyncio.run(main())
