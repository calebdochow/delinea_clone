from datetime import datetime

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Master password schemas
# ---------------------------------------------------------------------------

class MasterPasswordSetup(BaseModel):
    """Sent once to create the vault master password."""
    password: str = Field(..., min_length=8, max_length=128, description="Master password for the vault")


class MasterPasswordUnlock(BaseModel):
    """Sent to unlock the vault (start a session)."""
    password: str = Field(..., min_length=1, max_length=128)


class MasterPasswordStatus(BaseModel):
    """Reports whether the vault has been initialised."""
    is_setup: bool
    is_unlocked: bool


# ---------------------------------------------------------------------------
# Credential schemas
# ---------------------------------------------------------------------------

class CredentialCreate(BaseModel):
    """Data the client sends when saving a new credential."""
    site_name: str = Field(..., min_length=1, max_length=255)
    site_url: str | None = Field(default=None, max_length=2048)
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=1024, description="Plaintext password to encrypt and store")
    notes: str | None = Field(default=None, max_length=5000)


class CredentialUpdate(BaseModel):
    """Partial update for an existing credential. All fields are optional."""
    site_name: str | None = Field(default=None, min_length=1, max_length=255)
    site_url: str | None = Field(default=None, max_length=2048)
    username: str | None = Field(default=None, min_length=1, max_length=255)
    password: str | None = Field(default=None, min_length=1, max_length=1024)
    notes: str | None = Field(default=None, max_length=5000)


class CredentialRead(BaseModel):
    """Full credential including decrypted password."""
    id: int
    site_name: str
    site_url: str | None
    username: str
    password: str  # decrypted on-the-fly before returning
    notes: str | None
    created_at: datetime
    updated_at: datetime


class CredentialSummary(BaseModel):
    """Listing entry — password is hidden."""
    id: int
    site_name: str
    site_url: str | None
    username: str
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Password generator schemas (kept from earlier iteration)
# ---------------------------------------------------------------------------

class PasswordCreate(BaseModel):
    """Data the client sends when saving a generated password."""

    value: str = Field(..., min_length=1, max_length=1024, description="The generated password")
    label: str | None = Field(default=None, max_length=255, description="Optional friendly label")
    length: int = Field(..., ge=1, le=512, description="Length of the password")
    strength_score: int = Field(..., ge=0, le=100, description="0-100 strength score")
    strength_label: str = Field(..., max_length=32, description="e.g. 'Very Strong'")
    entropy_bits: int = Field(..., ge=0, description="Estimated entropy in bits")

    @field_validator("value")
    @classmethod
    def value_length_matches(cls, v: str, info) -> str:
        data = info.data
        if "length" in data and len(v) != data["length"]:
            raise ValueError("value length does not match the declared length field")
        return v


class PasswordRead(BaseModel):
    """Data returned when reading a password entry."""

    id: int
    label: str | None
    value: str
    length: int
    strength_score: int
    strength_label: str
    entropy_bits: int
    created_at: datetime

    model_config = {"from_attributes": True}


class PasswordSummary(BaseModel):
    """Lightweight listing entry — omits the password value itself."""

    id: int
    label: str | None
    length: int
    strength_score: int
    strength_label: str
    entropy_bits: int
    created_at: datetime

    model_config = {"from_attributes": True}
