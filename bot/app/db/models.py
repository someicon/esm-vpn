from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    telegram_id: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    peers: Mapped[list["Peer"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class Peer(Base):
    __tablename__ = "peers"
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_peer_user_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(64))
    # Only the *public* key is stored. The private key is generated on-demand,
    # handed to the user inside a .conf, and then discarded.
    public_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    assigned_ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Persisted copy of the latest handshake time seen from the WG kernel
    # session. Survives restarts of both the bot and the wireguard container.
    last_handshake_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship(back_populates="peers")
