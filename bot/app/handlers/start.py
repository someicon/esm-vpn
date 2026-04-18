from __future__ import annotations

from aiogram import Router
from aiogram.filters import CommandStart, Command
from aiogram.types import Message
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import repo

router = Router(name="start")


HELP_TEXT = (
    "WireGuard VPN bot\n\n"
    "Commands:\n"
    "/new <name> - create a new VPN peer and get the config\n"
    "/list - list your peers with status\n"
    "/delete <name> - delete a peer\n"
    "/help - show this help"
)


@router.message(CommandStart())
async def on_start(message: Message, session: AsyncSession) -> None:
    if message.from_user is None:
        return
    await repo.get_or_create_user(
        session,
        telegram_id=message.from_user.id,
        username=message.from_user.username,
    )
    await message.answer(HELP_TEXT)


@router.message(Command("help"))
async def on_help(message: Message) -> None:
    await message.answer(HELP_TEXT)
