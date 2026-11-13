"""
Orion Security Platform — FastAPI Dependencies & Quota Guards.

Provides:
- Database session injection (`get_db`)
- JWT authentication and token verification (`get_current_user`)
- Daily quota limiter (`check_daily_quota`): Free tier capped at 3 scans/day (HTTP 429).
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from orion.models.database import User, get_db

# ──────────────────────────────────────────────────────────────
# Security Settings
# ──────────────────────────────────────────────────────────────

SECRET_KEY = os.getenv("SECRET_KEY", "orion-super-secret-jwt-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours

import bcrypt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ──────────────────────────────────────────────────────────────
# Password Hashing & Token Helpers (Native bcrypt with 72-byte safety)
# ──────────────────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against the stored bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password[:72].encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Generates a secure bcrypt password hash."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password[:72].encode("utf-8"), salt).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Encodes a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ──────────────────────────────────────────────────────────────
# Authentication Dependency
# ──────────────────────────────────────────────────────────────

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Decodes the Bearer JWT token and returns the authenticated User record.
    Raises HTTP 401 Unauthorized if the token is missing, expired, or invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. Please log in.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exception

    return user


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Returns the authenticated User or None if unauthenticated (for public endpoints)."""
    if not token:
        return None
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None


# ──────────────────────────────────────────────────────────────
# Subscription Quota Guard Dependency
# ──────────────────────────────────────────────────────────────

async def check_daily_quota(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """
    Enforces the Free Tier daily scan limit (3 scans per 24 hours).
    Automatically resets the counter at midnight.
    Raises HTTP 429 Too Many Requests if the quota is exhausted.
    """
    today = date.today()

    # Reset quota if day has rolled over
    if user.last_scan_reset < today:
        user.scans_today = 0
        user.last_scan_reset = today
        db.commit()
        db.refresh(user)

    # Free plan enforcement
    if user.plan.lower() == "free":
        if user.scans_today >= 3:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Daily scan quota reached (3/3 scans used). Upgrade to Pro or Enterprise for unlimited scans.",
            )

    return user
