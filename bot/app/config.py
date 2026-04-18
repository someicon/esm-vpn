from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    bot_token: str = Field(..., alias="BOT_TOKEN")
    admin_ids_raw: str = Field(default="", alias="ADMIN_IDS")

    wg_container_name: str = Field(default="wireguard", alias="WG_CONTAINER_NAME")
    wg_interface: str = Field(default="wg0", alias="WG_INTERFACE")

    wg_server_endpoint: str = Field(..., alias="WG_SERVER_ENDPOINT")
    wg_server_port: int = Field(default=51820, alias="WG_SERVER_PORT")

    wg_network_raw: str = Field(default="10.0.0.0/22", alias="WG_NETWORK")
    wg_server_ip_raw: str = Field(default="10.0.0.1", alias="WG_SERVER_IP")
    wg_max_peers: int = Field(default=1000, alias="WG_MAX_PEERS")

    wg_egress_iface: str = Field(default="eth0", alias="WG_EGRESS_IFACE")
    wg_dns: str = Field(default="1.1.1.1", alias="WG_DNS")

    db_path: str = Field(default="/data/vpn.db", alias="DB_PATH")

    # Path inside the bot container where the WG server pubkey is available
    # (shared volume with the wireguard container).
    wg_server_pubkey_path: Path = Field(
        default=Path("/run/wg/server.pub"),
        alias="WG_SERVER_PUBKEY_PATH",
    )

    @field_validator("wg_max_peers")
    @classmethod
    def _max_peers_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("WG_MAX_PEERS must be positive")
        return v

    @property
    def admin_ids(self) -> set[int]:
        if not self.admin_ids_raw.strip():
            return set()
        return {
            int(chunk.strip())
            for chunk in self.admin_ids_raw.split(",")
            if chunk.strip()
        }

    @property
    def wg_network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.wg_network_raw, strict=False)

    @property
    def wg_server_ip(self) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(self.wg_server_ip_raw)

    @property
    def db_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
