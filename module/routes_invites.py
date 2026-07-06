"""
Staff invite & tenant access routes (Epic C7 / REQ-1.11, REQ-1.12).
"""

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .auth import get_current_user_required, get_password_hash
from .context_factory import get_db, get_module_context, get_redis_client
from .models import User, UserResponse
from .models.tenant_access import Invite, RestaurantAccess, generate_invite_token
from .services import (
    get_rbac_service,
    send_invite_email,
    user_can_manage_restaurant_staff,
)

router = APIRouter()


# ==================== Request/response models ====================


class InviteCreate(BaseModel):
    email: str
    restaurant_uuid: str
    role_name: str


class InviteResponse(BaseModel):
    token: str
    email: str
    restaurant_uuid: str
    role_name: str
    expires_at: str
    invite_link: str


class InviteAcceptRequest(BaseModel):
    username: str
    password: str
    passwordConfirm: str
    first_name: str | None = None
    last_name: str | None = None


class RevokeAccessResponse(BaseModel):
    message: str


async def _invite_expire_days(context) -> int:
    return int(context.get_module_config("INVITE_EXPIRE_DAYS", "authentication", 7))


def _invite_accept_url(context, token: str) -> str:
    base_url = context.get_module_config(
        "PUBLIC_BASE_URL", "authentication", "http://localhost:8085"
    )
    return f"{base_url.rstrip('/')}/authentication/invites/{token}/accept"


# ==================== Routes ====================


@router.post("/invites", response_model=InviteResponse)
async def create_invite(
    invite: InviteCreate,
    current_user: User = Depends(get_current_user_required()),
    db: Session = Depends(get_db),
):
    """Invite a user to join a restaurant's staff with a given role."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await user_can_manage_restaurant_staff(
        db, rbac, current_user.id, invite.restaurant_uuid
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage staff for this restaurant",
        )

    if invite.role_name == "ADMIN":
        raise HTTPException(
            status_code=400,
            detail="Cannot invite a user directly into the ADMIN role",
        )

    role = await rbac.get_role_by_name(invite.role_name)
    if not role:
        raise HTTPException(
            status_code=404, detail=f"Role '{invite.role_name}' not found"
        )

    context = get_module_context()
    expire_days = await _invite_expire_days(context)
    token = generate_invite_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=expire_days)

    db_invite = Invite(
        email=invite.email,
        restaurant_uuid=invite.restaurant_uuid,
        role_id=role.id,
        token=token,
        status="PENDING",
        invited_by_id=current_user.id,
        expires_at=expires_at,
    )
    db.add(db_invite)
    db.commit()
    db.refresh(db_invite)

    invite_link = _invite_accept_url(context, token)
    # Best-effort delivery: SMTP I/O runs off the event loop, and a failed
    # send never blocks invite creation - the Invite row + token are the
    # source of truth (see services/email_service.py).
    await asyncio.to_thread(
        send_invite_email, context, invite.email, invite_link, role.name
    )

    return InviteResponse(
        token=token,
        email=invite.email,
        restaurant_uuid=invite.restaurant_uuid,
        role_name=role.name,
        expires_at=expires_at.isoformat(),
        invite_link=invite_link,
    )


@router.post("/invites/{token}/accept", response_model=UserResponse)
async def accept_invite(
    token: str,
    body: InviteAcceptRequest,
    db: Session = Depends(get_db),
):
    """Accept a staff invite and create the invited user's account. No auth required."""
    db_invite = db.query(Invite).filter(Invite.token == token).first()
    if not db_invite:
        raise HTTPException(status_code=404, detail="Invite not found")

    if db_invite.status != "PENDING":
        raise HTTPException(status_code=400, detail="Invite is no longer valid")

    expires_at = db_invite.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invite has expired")

    if body.password != body.passwordConfirm:
        raise HTTPException(status_code=400, detail="Passwords should match")

    existing = (
        db.query(User)
        .filter((User.username == body.username) | (User.email == db_invite.email))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400, detail="Username or email already registered"
        )

    hashed_password = get_password_hash(body.password)
    new_user = User(
        username=body.username,
        email=db_invite.email,
        password_hash=hashed_password,
        first_name=body.first_name,
        last_name=body.last_name,
    )
    db.add(new_user)
    db.flush()

    # Tenant role is attached ONLY via RestaurantAccess.role_id, never via
    # user.roles - that would grant the role's privileges globally instead of
    # scoped to this one restaurant.
    db.add(
        RestaurantAccess(
            user_id=new_user.id,
            restaurant_uuid=db_invite.restaurant_uuid,
            role_id=db_invite.role_id,
            invited_by_id=db_invite.invited_by_id,
        )
    )

    db_invite.status = "ACCEPTED"
    db_invite.accepted_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(new_user)

    return UserResponse(
        uuid=str(new_user.uuid),
        username=new_user.username,
        first_name=new_user.first_name,
        middle_name=new_user.middle_name,
        last_name=new_user.last_name,
        email=new_user.email,
        is_active=new_user.is_active,
    )


@router.delete("/users/{uuid}/access", response_model=RevokeAccessResponse)
async def revoke_restaurant_access(
    uuid: str,
    restaurant_uuid: str = Query(..., description="Restaurant to revoke access for"),
    current_user: User = Depends(get_current_user_required()),
    db: Session = Depends(get_db),
):
    """Instantly revoke a user's tenant-scoped access to one restaurant."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await user_can_manage_restaurant_staff(
        db, rbac, current_user.id, restaurant_uuid
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage staff for this restaurant",
        )

    target_user = db.query(User).filter(User.uuid == uuid).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    access = (
        db.query(RestaurantAccess)
        .filter(
            RestaurantAccess.user_id == target_user.id,
            RestaurantAccess.restaurant_uuid == restaurant_uuid,
        )
        .first()
    )
    if not access:
        raise HTTPException(status_code=404, detail="Access grant not found")

    db.delete(access)
    db.commit()

    return RevokeAccessResponse(message="Access revoked")
