from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Role, SignupToken, utcnow
from app.security import generate_signup_token, hash_signup_token


def issue_signup_token(
    db: Session,
    *,
    role: Role,
    created_by_id: str | None,
    expires_in_minutes: int,
    token_pepper: str,
) -> tuple[SignupToken, str]:
    plaintext_token = generate_signup_token()
    token_hash = hash_signup_token(plaintext_token, token_pepper)

    token = SignupToken(
        token_hash=token_hash,
        token_hint=plaintext_token.split("-")[0],
        role_to_grant=role,
        created_by_id=created_by_id,
        expires_at=utcnow() + timedelta(minutes=expires_in_minutes),
    )
    db.add(token)
    db.flush()
    return token, plaintext_token


def get_valid_signup_token(db: Session, *, token: str, token_pepper: str) -> SignupToken | None:
    token_hash = hash_signup_token(token, token_pepper)
    stmt = select(SignupToken).where(SignupToken.token_hash == token_hash)
    record = db.scalar(stmt)
    if not record:
        return None
    if record.used_at is not None:
        return None
    if record.expires_at <= utcnow():
        return None
    return record


def consume_signup_token(record: SignupToken, *, used_by_id: str) -> None:
    record.used_at = utcnow()
    record.used_by_id = used_by_id
