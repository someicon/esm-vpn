from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

from app.config import get_settings
from app.db import repo
from app.db.session import get_session_factory, init_db
from app.handlers import build_router
from app.middlewares.auth import AdminOnlyMiddleware
from app.middlewares.db import DbSessionMiddleware
from app.services.wg import WireGuardError, WireGuardService

logger = logging.getLogger(__name__)


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


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    settings = get_settings()

    await init_db()

    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
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

    logger.info("bot starting (polling)")
    await dp.start_polling(bot, wg=wg)


if __name__ == "__main__":
    asyncio.run(main())
