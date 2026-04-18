from __future__ import annotations

import io
import ipaddress
from dataclasses import dataclass

import qrcode


@dataclass(frozen=True, slots=True)
class ClientConfig:
    text: str
    filename: str

    def qr_png_bytes(self) -> bytes:
        img = qrcode.make(self.text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()


def build_client_config(
    *,
    client_private_key: str,
    client_ip: ipaddress.IPv4Address | str,
    dns: str,
    server_public_key: str,
    server_endpoint: str,
    preshared_key: str | None = None,
    peer_name: str = "wg",
    keepalive_seconds: int = 25,
) -> ClientConfig:
    """Render a client-side wg .conf as plain text (never written to disk)."""
    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_ip}/32",
        f"DNS = {dns}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
    ]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.extend(
        [
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"Endpoint = {server_endpoint}",
            f"PersistentKeepalive = {keepalive_seconds}",
            "",
        ]
    )
    text = "\n".join(lines)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in peer_name) or "wg"
    return ClientConfig(text=text, filename=f"{safe_name}.conf")
