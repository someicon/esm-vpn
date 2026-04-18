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

HANDSHAKE_SYNC_INTERVAL_S = 60


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


async def _handshake_sync_loop(
    wg: WireGuardService,
    session_factory: async_sessionmaker[AsyncSession],
    interval_s: int = HANDSHAKE_SYNC_INTERVAL_S,
) -> None:
    """Periodically snapshot runtime handshake times into the DB.

    Runs forever until cancelled. We deliberately never surface WG errors as
    task failures — if the wireguard container is temporarily down, we just
    wait for the next tick.
    """
    while True:
        try:
            runtime_peers = await wg.list_peers()
        except WireGuardError as exc:
            logger.warning("handshake sync: wg unavailable: %s", exc)
            runtime_peers = []
        except Exception:
            logger.exception("handshake sync: unexpected error, backing off")
            runtime_peers = []

        updates: dict[str, datetime] = {
            p.public_key: datetime.fromtimestamp(p.latest_handshake, tz=timezone.utc)
            for p in runtime_peers
            if p.latest_handshake > 0
        }

        if updates:
            try:
                async with session_factory() as session:
                    await repo.update_peer_handshakes(session, updates)
                    await session.commit()
            except Exception:
                logger.exception("handshake sync: DB write failed")

        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            logger.info("handshake sync: cancelled, exiting")
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
        _handshake_sync_loop(wg, get_session_factory()),
        name="handshake-sync",
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
