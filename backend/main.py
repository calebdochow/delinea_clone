from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .encryption import (
    decrypt_password,
    derive_key,
    encrypt_password,
    generate_salt,
    hash_master_password,
    verify_master_password,
)
from .models import Credential, MasterKey, Password
from .schemas import (
    CredentialCreate,
    CredentialRead,
    CredentialSummary,
    CredentialUpdate,
    MasterPasswordSetup,
    MasterPasswordStatus,
    MasterPasswordUnlock,
    PasswordCreate,
    PasswordRead,
    PasswordSummary,
)

# Create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PassGuard API",
    description="Password manager  vault backed by SQLite with Fernet encryption.",
    version="0.2.0",
)

# Allow the local HTML frontend to call the API during development.
# Tighten origins before deploying to production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


#in-memory variable when the vault is unlocked, and cleared when locked.
_session: dict[str, bytes | None] = {"encryption_key": None}


def _require_unlocked() -> bytes:
    """Dependency-style helper — raises 403 if the vault is locked."""
    key = _session["encryption_key"]
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked. POST /vault/unlock first.",
        )
    return key


# Vault / master-password routes
@app.get(
    "/vault/status",
    response_model=MasterPasswordStatus,
    summary="Check whether the vault is set up and/or unlocked",
)
def vault_status(db: Session = Depends(get_db)) -> dict:
    master = db.get(MasterKey, 1)
    return {
        "is_setup": master is not None,
        "is_unlocked": _session["encryption_key"] is not None,
    }

@app.post(
    "/vault/setup",
    response_model=MasterPasswordStatus,
    status_code=status.HTTP_201_CREATED,
    summary="Create the master password (first-time setup)",
)
def vault_setup(payload: MasterPasswordSetup, db: Session = Depends(get_db)) -> dict:
    if db.get(MasterKey, 1) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Master password already configured.",
        )
    salt = generate_salt()
    master = MasterKey(
        id=1,
        password_hash=hash_master_password(payload.password),
        salt=salt,
    )
    db.add(master)
    db.commit()

    # Auto-unlock after setup
    _session["encryption_key"] = derive_key(payload.password, salt)
    return {"is_setup": True, "is_unlocked": True}


@app.post(
    "/vault/unlock",
    response_model=MasterPasswordStatus,
    summary="Unlock the vault with the master password",
)
def vault_unlock(payload: MasterPasswordUnlock, db: Session = Depends(get_db)) -> dict:
    master = db.get(MasterKey, 1)
    if master is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vault not set up yet. POST /vault/setup first.",
        )
    if not verify_master_password(payload.password, master.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password.",
        )
    _session["encryption_key"] = derive_key(payload.password, master.salt)
    return {"is_setup": True, "is_unlocked": True}


@app.post(
    "/vault/lock",
    response_model=MasterPasswordStatus,
    summary="Lock the vault (clear the in-memory key)",
)
def vault_lock(db: Session = Depends(get_db)) -> dict:
    _session["encryption_key"] = None
    master = db.get(MasterKey, 1)
    return {"is_setup": master is not None, "is_unlocked": False}


#Credential Routes

@app.post(
    "/credentials",
    response_model=CredentialRead,
    status_code=status.HTTP_201_CREATED,
    summary="Save a new credential",
)
def create_credential(payload: CredentialCreate, db: Session = Depends(get_db)) -> dict:
    key = _require_unlocked()
    entry = Credential(
        site_name=payload.site_name,
        site_url=payload.site_url,
        username=payload.username,
        encrypted_password=encrypt_password(payload.password, key),
        notes=payload.notes,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return _credential_to_read(entry, key)


@app.get(
    "/credentials",
    response_model=list[CredentialSummary],
    summary="List all saved credentials (passwords hidden)",
)
def list_credentials(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[Credential]:
    _require_unlocked()
    return (
        db.query(Credential)
        .order_by(Credential.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.get(
    "/credentials/{credential_id}",
    response_model=CredentialRead,
    summary="Retrieve a single credential (password decrypted)",
)
def get_credential(credential_id: int, db: Session = Depends(get_db)) -> dict:
    key = _require_unlocked()
    entry = db.get(Credential, credential_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    return _credential_to_read(entry, key)


@app.put(
    "/credentials/{credential_id}",
    response_model=CredentialRead,
    summary="Update an existing credential",
)
def update_credential(
    credential_id: int,
    payload: CredentialUpdate,
    db: Session = Depends(get_db),
) -> dict:
    key = _require_unlocked()
    entry = db.get(Credential, credential_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")

    update_data = payload.model_dump(exclude_unset=True)
    if "password" in update_data:
        entry.encrypted_password = encrypt_password(update_data.pop("password"), key)
    for field, value in update_data.items():
        setattr(entry, field, value)

    db.commit()
    db.refresh(entry)
    return _credential_to_read(entry, key)


@app.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a saved credential",
)
def delete_credential(credential_id: int, db: Session = Depends(get_db)) -> None:
    _require_unlocked()
    entry = db.get(Credential, credential_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    db.delete(entry)
    db.commit()


def _credential_to_read(entry: Credential, key: bytes) -> dict:
    """Convert a Credential ORM object to a CredentialRead-compatible dict."""
    return {
        "id": entry.id,
        "site_name": entry.site_name,
        "site_url": entry.site_url,
        "username": entry.username,
        "password": decrypt_password(entry.encrypted_password, key),
        "notes": entry.notes,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
    }


#Password Routes

@app.post(
    "/passwords",
    response_model=PasswordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Save a generated password",
)
def create_password(payload: PasswordCreate, db: Session = Depends(get_db)) -> Password:
    entry = Password(**payload.model_dump())
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@app.get(
    "/passwords",
    response_model=list[PasswordSummary],
    summary="List all saved passwords (values hidden)",
)
def list_passwords(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[Password]:
    return db.query(Password).order_by(Password.created_at.desc()).offset(skip).limit(limit).all()


@app.get(
    "/passwords/{password_id}",
    response_model=PasswordRead,
    summary="Retrieve a single saved password by ID",
)
def get_password(password_id: int, db: Session = Depends(get_db)) -> Password:
    entry = db.get(Password, password_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Password not found")
    return entry


@app.delete(
    "/passwords/{password_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a saved password",
)
def delete_password(password_id: int, db: Session = Depends(get_db)) -> None:
    entry = db.get(Password, password_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Password not found")
    db.delete(entry)
    db.commit()
