from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .models import User
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError
from .context_factory import get_module_context

ph = PasswordHasher()

ALGORITHM = "HS256"

security = HTTPBearer()

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
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token."""
    
    context = get_module_context()
    
    SECRET_KEY = context.get_module_config("SECRET_KEY", "authentication", None)
    
    if not SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SECRET_KEY not configured"
        )
    
    if context is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Module not initialized"
        )
    
    db = await anext(context.get_db())
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user