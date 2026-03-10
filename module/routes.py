
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .models import User, UserCreate, UserLogin, Token, UserResponse
from .auth import get_current_user, authenticate_user, create_access_token, get_password_hash
from .context_factory import get_module_context
from datetime import timedelta

router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_db():
    """Get database session from module context."""
    context = get_module_context()
    if context is None:
        raise HTTPException(status_code=500, detail="Module not initialized")
    return context.get_db()


@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate, current_user = Depends(get_current_user)):
    db = next(get_db())
    db_user = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return UserResponse(id=db_user.id, username=db_user.username, email=db_user.email, is_active=db_user.is_active, role=db_user.role)


@router.post("/login", response_model=Token)
async def login(user: UserLogin):
    db = await anext(get_db())
    db_user = authenticate_user(db, user.username, user.password)
    if not db_user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": db_user.username}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return UserResponse(id=current_user.id, username=current_user.username, email=current_user.email, is_active=current_user.is_active, role=current_user.role)


@router.put("/me", response_model=UserResponse)
async def update_user_me(user_update: UserCreate, current_user: User = Depends(get_current_user)):
    db = next(get_db())
    current_user.username = user_update.username
    current_user.email = user_update.email
    if user_update.password:
        current_user.password_hash = get_password_hash(user_update.password)
    db.commit()
    db.refresh(current_user)
    return UserResponse(id=current_user.id, username=current_user.username, email=current_user.email, is_active=current_user.is_active, role=current_user.role)


@router.delete("/me")
async def delete_user_me(current_user: User = Depends(get_current_user)):
    db = next(get_db())
    db.delete(current_user)
    db.commit()
    return {"message": "User deleted"}


@router.get("/users", response_model=list[UserResponse])
async def read_users(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_user)):
    db = next(get_db())
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserResponse(id=u.id, username=u.username, email=u.email, is_active=u.is_active, role=u.role) for u in users]
