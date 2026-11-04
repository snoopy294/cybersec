"""SENTINEL — Auth service for JWT token management and password hashing."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Verified against when the email is unknown, so a failed login costs the same
# time whether or not the account exists.
_DUMMY_PASSWORD_HASH = pwd_context.hash("sentinel-timing-equalizer-not-a-real-password")

TOKEN_TYPE = "access"


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """Verify a password against its hash, spending equal time on unknown users."""
    try:
        if not hashed_password:
            pwd_context.verify(plain_password, _DUMMY_PASSWORD_HASH)
            return False
        return pwd_context.verify(plain_password, hashed_password)
    except (ValueError, TypeError):
        # Malformed hash or a password bcrypt refuses; never a valid login.
        return False


def create_access_token(user_id: UUID, tenant_id: UUID) -> str:
    """Create a JWT access token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "type": TOKEN_TYPE,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """Decode and validate a JWT token. Returns payload or None."""
    if not token or len(token) > 4096:
        return None
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require_exp": True, "require_sub": True},
        )
    except JWTError:
        return None
    if payload.get("type") != TOKEN_TYPE:
        return None
    return payload
