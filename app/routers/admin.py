from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.deps import get_admin_user, get_superadmin_user
from app.models import SignupToken, User
from app.schemas import (
    CreateSignupTokenRequest,
    CreateSignupTokenResponse,
    SignupModeResponse,
    SignupTokenListResponse,
    SignupTokenSummary,
    UpdateSignupModeRequest,
)
from app.services.settings_service import get_public_signup_mode, set_public_signup_mode
from app.services.token_service import issue_signup_token

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/settings/public-signup-mode", response_model=SignupModeResponse)
def get_signup_mode(
    _: User = Depends(get_admin_user),
    db: Session = Depends(get_db),
) -> SignupModeResponse:
    return SignupModeResponse(mode=get_public_signup_mode(db))


@router.put("/settings/public-signup-mode", response_model=SignupModeResponse)
def update_signup_mode(
    payload: UpdateSignupModeRequest,
    current_user: User = Depends(get_superadmin_user),
    db: Session = Depends(get_db),
) -> SignupModeResponse:
    mode = set_public_signup_mode(db, mode=payload.mode, actor_user_id=current_user.id)
    return SignupModeResponse(mode=mode)


@router.post("/signup-tokens", response_model=CreateSignupTokenResponse)
def create_signup_token(
    payload: CreateSignupTokenRequest,
    current_user: User = Depends(get_superadmin_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> CreateSignupTokenResponse:
    token_record, token = issue_signup_token(
        db,
        role=payload.role,
        created_by_id=current_user.id,
        expires_in_minutes=payload.expires_in_minutes,
        token_pepper=settings.token_pepper,
    )
    db.commit()
    db.refresh(token_record)

    return CreateSignupTokenResponse(
        token=token,
        token_hint=token_record.token_hint,
        role=token_record.role_to_grant,
        expires_at=token_record.expires_at,
    )


@router.get("/signup-tokens", response_model=SignupTokenListResponse)
def list_signup_tokens(
    _: User = Depends(get_superadmin_user),
    db: Session = Depends(get_db),
) -> SignupTokenListResponse:
    items = (
        db.execute(select(SignupToken).order_by(desc(SignupToken.created_at)).limit(100))
        .scalars()
        .all()
    )
    return SignupTokenListResponse(items=[SignupTokenSummary.model_validate(item) for item in items])
