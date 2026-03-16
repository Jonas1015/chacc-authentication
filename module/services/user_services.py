from sqlalchemy.orm import Session

from fastapi import Request
from chacc_api import BackboneContext, RedisService

from ..auth import get_password_hash
from ..models import User, Token, TokenRefreshRequest, RevokeRequest
from .oauth2_service import OAuth2Service
from ..context_factory import get_module_context
from datetime import timedelta, datetime, timezone

async def create_default_user(context):
    """
    Create a default admin user if no users exist.
    Uses environment variables for configuration:
    - DEFAULT_ADMIN_USERNAME: Default admin username (default: "admin")
    - DEFAULT_ADMIN_PASSWORD: Default admin password (default: "admin123")
    """
    _module_context = context if context else get_module_context()
    
    default_username = _module_context.get_module_config("DEFAULT_ADMIN_USERNAME", "authentication", "admin")
    default_password = _module_context.get_module_config("DEFAULT_ADMIN_PASSWORD", "authentication", "admin123")
    
    db: Session = await anext(_module_context.get_db())
    
    user_count = db.query(User).count()
    if user_count > 0:
        _module_context.logger.info(f"Users already exist ({user_count}), skipping default user creation")
        return
    
    hashed_password = get_password_hash(default_password)
    default_user = User(
        username=default_username,
        email=f"{default_username}@chacc.local",
        password_hash=hashed_password,
        is_active=True,
        role="admin"
    )
    
    db.add(default_user)
    db.commit()
    db.refresh(default_user)
    
    _module_context.logger.info(f"Created default admin user: {default_username}")
    _module_context.logger.warning("DEFAULT CREDENTIALS - Please change the default password in production!")


async def get_token_expiry_settings(context):
    """Get token expiry settings from module config."""
    access_token_expire_minutes = int(context.get_module_config("ACCESS_TOKEN_EXPIRE_MINUTES", "authentication", 30))
    refresh_token_expire_days = int(context.get_module_config("REFRESH_TOKEN_EXPIRE_DAYS", "authentication", 7))
    return access_token_expire_minutes, refresh_token_expire_days


async def login_user(db: Session, user: User, request: Request, context: BackboneContext) -> Token:
    """
    Authenticate user and create OAuth2 session.
    Returns Token with access and refresh tokens.
    """
    redis_service: RedisService = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()
    
    access_token_expire_minutes, refresh_token_expire_days = await get_token_expiry_settings(context)
    
    ip_address = request.client.host if request.client else None
    device_info = request.headers.get("user-agent", "Unknown")
    
    oauth_service = OAuth2Service(db, redis_client)
    expires_delta = timedelta(minutes=access_token_expire_minutes)
    expires_at = datetime.now(timezone.utc) + expires_delta
    
    access_token, refresh_token, session_uuid = await oauth_service.create_session(
        user=user,
        expires_delta=expires_delta,
        device_info=device_info,
        ip_address=ip_address
    )
    
    refresh_token_expiry = refresh_token_expire_days * 24 * 60 * 60
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=access_token_expire_minutes * 60,
        expires_at=expires_at.isoformat(),
        access_token_expiry=access_token_expire_minutes * 60,
        refresh_token_expiry=refresh_token_expiry
    )


async def refresh_token(db: Session, token_request: TokenRefreshRequest, request: Request, context: BackboneContext) -> Token:
    """
    Refresh access token using a valid refresh token.
    Returns new Token with rotated tokens.
    """
    redis_service = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()
    
    access_token_expire_minutes, refresh_token_expire_days = await get_token_expiry_settings(context)
    
    ip_address = request.client.host if request.client else None
    device_info = request.headers.get("user-agent", "Unknown")
    
    oauth_service = OAuth2Service(db, redis_client)
    expires_delta = timedelta(minutes=access_token_expire_minutes)
    
    result = await oauth_service.rotate_session(
        old_refresh_token=token_request.refresh_token,
        new_expires_delta=expires_delta,
        device_info=device_info,
        ip_address=ip_address
    )
    
    if result is None:
        return None
    
    expires_at = datetime.now(timezone.utc) + expires_delta
    access_token, refresh_token, session_uuid = result
    
    refresh_token_expiry = refresh_token_expire_days * 24 * 60 * 60
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=access_token_expire_minutes * 60,
        expires_at=expires_at.isoformat(),
        access_token_expiry=access_token_expire_minutes * 60,
        refresh_token_expiry=refresh_token_expiry
    )


async def revoke_token(db: Session, revoke_request: RevokeRequest, context) -> bool:
    """Revoke a refresh token (logout from specific device/session)."""
    redis_service = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()
    
    oauth_service = OAuth2Service(db, redis_client)
    return await oauth_service.revoke_session(revoke_request.refresh_token)


async def logout_all_sessions(db: Session, user_id: int, context) -> int:
    """Logout current user from all devices (revoke all sessions)."""
    redis_service = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()
    
    oauth_service = OAuth2Service(db, redis_client)
    return await oauth_service.revoke_all_user_sessions(user_id)