from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError

from chacc_authentication.module.models.user import User
from chacc_authentication.module.context_factory import get_module_context

ph = PasswordHasher()

ALGORITHM = "HS256"

security = HTTPBearer(auto_error=False)


def verify_password(plain_password, hashed_password):
    try:
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False


def get_password_hash(password):
    try:
        return ph.hash(password)
    except HashingError:
        return None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):

    context = get_module_context()

    if context is None:
        raise RuntimeError("Module not initialized - cannot create access token")

    SECRET_KEY = context.get_module_config("SECRET_KEY", "authentication", None)

    if not SECRET_KEY:
        raise ValueError(
            "SECRET_KEY not configured for authentication module. "
            "Please set SECRET_KEY in your environment variables."
        )

    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(db: Session, username: str, password: str):
    user: User = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    """Get current user from JWT token. Returns None if no valid credentials provided."""

    context = get_module_context()

    if context is None:
        return None

    SECRET_KEY = context.get_module_config("SECRET_KEY", "authentication", None)

    if not SECRET_KEY:
        return None

    if not credentials:
        return None

    db = await anext(context.get_db())

    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            return None
    except JWTError:
        return None
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        return None
    return user


def get_current_user_required():
    """
    Returns a dependency that raises 401 if not authenticated.
    Use this for routes that require authentication.
    """

    async def _get_current_user_required(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        user = await get_current_user(credentials)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user

    return _get_current_user_required
