"""
Orion Security Platform — Authentication & Profile Routes.

Endpoints:
  POST /api/auth/register — Create account (Free plan default)
  POST /api/auth/login    — Authenticate & receive Bearer JWT
  GET  /api/auth/me       — Fetch authenticated profile & quota status
  PUT  /api/auth/settings — Update user settings & AI provider preferences
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from orion.api.deps import (
    create_access_token,
    get_current_user,
    get_db,
    get_password_hash,
    verify_password,
)
from orion.models.database import User
from orion.models.schemas import (
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
    UserSettingsUpdate,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user account on the Free plan and returns an access token."""
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists.",
        )

    user = User(
        email=payload.email,
        username=payload.username or payload.email.split("@")[0],
        hashed_password=get_password_hash(payload.password),
        plan="free",
        scans_today=0,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(data={"sub": str(user.id), "email": user.email})
    return TokenResponse(access_token=token, user=UserResponse.model_validate(user))


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    """Authenticates credentials and returns a Bearer JWT access token."""
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    token = create_access_token(data={"sub": str(user.id), "email": user.email})
    return TokenResponse(access_token=token, user=UserResponse.model_validate(user))


@router.get("/me", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user profile along with current plan and scan count."""
    return UserResponse.model_validate(current_user)


@router.put("/settings", response_model=UserResponse)
def update_settings(
    payload: UserSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Updates user profile preferences, including custom AI provider & BYOK configuration."""
    if payload.username is not None:
        current_user.username = payload.username
    if payload.ai_provider is not None:
        current_user.ai_provider = payload.ai_provider
    if payload.ai_api_key is not None:
        current_user.ai_api_key = payload.ai_api_key
    if payload.ai_base_url is not None:
        current_user.ai_base_url = payload.ai_base_url
    if payload.ai_model is not None:
        current_user.ai_model = payload.ai_model

    db.commit()
    db.refresh(current_user)
    return UserResponse.model_validate(current_user)

