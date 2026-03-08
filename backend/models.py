from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class MasterKey(Base):
    """Stores the hashed master password and the PBKDF2 salt used to derive
    the encryption key.  Only one row should ever exist (id=1)."""

    __tablename__ = "master_key"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Credential(Base):
    """A saved login credential — the password field is Fernet-encrypted."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    site_name: Mapped[str] = mapped_column(String(255), nullable=False)
    site_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_password: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Password(Base):
    """Stores a single generated password entry (legacy / quick-save)."""

    __tablename__ = "passwords"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    strength_score: Mapped[int] = mapped_column(Integer, nullable=False)
    strength_label: Mapped[str] = mapped_column(String(32), nullable=False)
    entropy_bits: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
