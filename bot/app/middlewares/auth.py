from __future__ import annotations

from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject


class AdminOnlyMiddleware(BaseMiddleware):
    """Restrict bot usage to a whitelist of Telegram user IDs.

    If `admin_ids` is empty, the middleware is a no-op (open bot).
    """

    def __init__(self, admin_ids: set[int]) -> None:
        self._admin_ids = admin_ids

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not self._admin_ids:
            return await handler(event, data)

        user = data.get("event_from_user")
        if user is None or user.id not in self._admin_ids:
            if isinstance(event, Message):
                await event.answer("Access denied.")
            return None

        return await handler(event, data)
