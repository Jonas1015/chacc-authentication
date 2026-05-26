from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from chacc_api import BackboneContext
from typing import Optional

from .models import User, UserCreate, UserLogin, Token, UserResponse
from .models.request_models import TokenRefreshRequest, RevokeRequest
from .auth import (
    get_current_user,
    get_current_user_required,
    authenticate_user,
    get_password_hash,
)
from .context_factory import get_module_context, get_db
from .services import login_user, refresh_token, revoke_token, logout_all_sessions

router = APIRouter()

registerRouter = APIRouter()


@registerRouter.post("/register", response_model=UserResponse)
async def register(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: Optional[UserResponse] = Depends(get_current_user),
):
    db_user = (
        db.query(User)
        .filter((User.username == user.username) | (User.email == user.email))
        .first()
    )
    if db_user:
        raise HTTPException(
            status_code=400, detail="Username or email already registered"
        )

    if user.password != user.passwordConfirm:
        raise HTTPException(status_code=400, detail="Passwords should match")

    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return UserResponse(
        uuid=db_user.uuid,
        username=db_user.username,
        first_name=db_user.first_name,
        middle_name=db_user.middle_name,
        last_name=db_user.last_name,
        email=db_user.email,
        is_active=db_user.is_active,
    )


@router.post("/login", response_model=Token)
async def login(user: UserLogin, request: Request, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user.username, user.password)
    if not db_user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    context = get_module_context()
    return await login_user(db, db_user, request, context)


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user_required())):
    return UserResponse(
        uuid=str(current_user.uuid),
        username=current_user.username,
        first_name=current_user.first_name,
        middle_name=current_user.middle_name,
        last_name=current_user.last_name,
        email=current_user.email,
        is_active=current_user.is_active,
    )


@router.put("/me", response_model=UserResponse)
async def update_user_me(
    user_update: UserCreate,
    current_user: User = Depends(get_current_user_required()),
    db: Session = Depends(get_db),
):
    current_user.username = user_update.username
    current_user.email = user_update.email
    if user_update.first_name:
        current_user.first_name = user_update.first_name
    if user_update.last_name:
        current_user.last_name = user_update.last_name
    if user_update.password:
        current_user.password_hash = get_password_hash(user_update.password)
    db.commit()
    db.refresh(current_user)
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
    )


@router.delete("/me")
async def delete_user_me(
    current_user: User = Depends(get_current_user_required()),
    db: Session = Depends(get_db),
):
    db.delete(current_user)
    db.commit()
    return {"message": "User deleted"}


@router.get("/users", response_model=list[UserResponse])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user_required()),
    db: Session = Depends(get_db),
):
    users = db.query(User).offset(skip).limit(limit).all()
    return [
        UserResponse(id=u.id, username=u.username, email=u.email, is_active=u.is_active)
        for u in users
    ]


@router.post("/refresh", response_model=Token)
async def refresh_token_endpoint(
    token_request: TokenRefreshRequest, request: Request, db: Session = Depends(get_db)
):
    """Refresh access token using a valid refresh token."""
    context = get_module_context()

    token = await refresh_token(db, token_request, request, context)

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    return token


@router.post("/revoke")
async def revoke_token_endpoint(
    revoke_request: RevokeRequest, db: Session = Depends(get_db)
):
    """Revoke a refresh token (logout from specific device/session)."""
    context = get_module_context()

    success = await revoke_token(db, revoke_request, context)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
        )

    return {"message": "Token revoked successfully"}


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user_required()),
    db: Session = Depends(get_db),
):
    """Logout current user from all devices (revoke all sessions)."""
    context = get_module_context()

    count = await logout_all_sessions(db, current_user.id, context)

    return {"message": f"Logged out from {count} session(s)"}
