
from fastapi import APIRouter, Depends, HTTPException, status, Request
from chacc_api import BackboneContext
from .models import User, UserCreate, UserLogin, Token, UserResponse
from .models.request_models import TokenRefreshRequest, RevokeRequest
from .auth import get_current_user, authenticate_user, get_password_hash
from .context_factory import get_module_context
from .services import login_user, refresh_token, revoke_token, logout_all_sessions

router = APIRouter()

def get_db():
    """Get database session from module context."""
    context: BackboneContext  = get_module_context()
    if context is None:
        raise HTTPException(status_code=500, detail="Module not initialized")
    return context.get_db()

@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate, current_user = Depends(get_current_user)):
    db = await anext(get_db())
    db_user = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return UserResponse(id=db_user.id, username=db_user.username, email=db_user.email, is_active=db_user.is_active)


@router.post("/login", response_model=Token)
async def login(user: UserLogin, request: Request):
    db = await anext(get_db())
    db_user = authenticate_user(db, user.username, user.password)
    if not db_user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    context = get_module_context()
    return await login_user(db, db_user, request, context)


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return UserResponse(id=current_user.id, username=current_user.username, email=current_user.email, is_active=current_user.is_active)


@router.put("/me", response_model=UserResponse)
async def update_user_me(user_update: UserCreate, current_user: User = Depends(get_current_user)):
    db = await anext(get_db())
    current_user.username = user_update.username
    current_user.email = user_update.email
    if user_update.password:
        current_user.password_hash = get_password_hash(user_update.password)
    db.commit()
    db.refresh(current_user)
    return UserResponse(id=current_user.id, username=current_user.username, email=current_user.email, is_active=current_user.is_active)


@router.delete("/me")
async def delete_user_me(current_user: User = Depends(get_current_user)):
    db = await anext(get_db())
    db.delete(current_user)
    db.commit()
    return {"message": "User deleted"}


@router.get("/users", response_model=list[UserResponse])
async def read_users(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_user)):
    db = await anext(get_db())
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserResponse(id=u.id, username=u.username, email=u.email, is_active=u.is_active) for u in users]


@router.post("/refresh", response_model=Token)
async def refresh_token_endpoint(token_request: TokenRefreshRequest, request: Request):
    """Refresh access token using a valid refresh token."""
    db = await anext(get_db())
    context = get_module_context()
    
    token = await refresh_token(db, token_request, request, context)
    
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    return token


@router.post("/revoke")
async def revoke_token_endpoint(revoke_request: RevokeRequest):
    """Revoke a refresh token (logout from specific device/session)."""
    db = await anext(get_db())
    context = get_module_context()
    
    success = await revoke_token(db, revoke_request, context)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return {"message": "Token revoked successfully"}


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout current user from all devices (revoke all sessions)."""
    db = await anext(get_db())
    context = get_module_context()
    
    count = await logout_all_sessions(db, current_user.id, context)
    
    return {"message": f"Logged out from {count} session(s)"}
