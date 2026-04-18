from __future__ import annotations

import asyncio
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class KeyPair:
    private_key: str
    public_key: str


async def _run(cmd: list[str], stdin: bytes | None = None) -> bytes:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate(input=stdin)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(cmd)} failed ({proc.returncode}): {err.decode(errors='replace').strip()}"
        )
    return out


async def generate_keypair() -> KeyPair:
    private = (await _run(["wg", "genkey"])).decode().strip()
    public = (await _run(["wg", "pubkey"], stdin=private.encode() + b"\n")).decode().strip()
    return KeyPair(private_key=private, public_key=public)


async def generate_preshared_key() -> str:
    return (await _run(["wg", "genpsk"])).decode().strip()
