from aiogram import Router

from . import start, vpn


def build_router() -> Router:
    router = Router(name="root")
    router.include_router(start.router)
    router.include_router(vpn.router)
    return router
