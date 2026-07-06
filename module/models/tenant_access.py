"""
Tenant-scoped staff access models for Epic C7 (REQ-1.11, REQ-1.12).

RestaurantAccess: the user <-> restaurant association ("who is staff of which
restaurant, with which Role"). restaurant_uuid is a plain indexed String, NOT
a real FK, because Restaurant lives in the `menu` plugin's own model module,
which this plugin must never import (plugin isolation).

Invite: a pending/accepted/revoked invitation token that, once accepted,
creates both a User and a RestaurantAccess row.
"""

import secrets

from chacc_api import ChaCCBaseModel, register_model
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship


@register_model
class RestaurantAccess(ChaCCBaseModel):
    """A user's tenant-scoped role grant for one restaurant."""

    __tablename__ = "restaurant_access"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "restaurant_uuid", name="uq_restaurant_access_user_restaurant"
        ),
    )

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    restaurant_uuid = Column(String(36), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    invited_by_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    user = relationship(
        "User", foreign_keys=[user_id], backref="restaurant_access_grants"
    )
    role = relationship("Role")
    invited_by = relationship("User", foreign_keys=[invited_by_id])


@register_model
class Invite(ChaCCBaseModel):
    """A pending/accepted/revoked staff invitation."""

    __tablename__ = "invites"

    email = Column(String, nullable=False, index=True)
    restaurant_uuid = Column(String(36), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, nullable=False, default="PENDING")  # PENDING/ACCEPTED/REVOKED
    invited_by_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    accepted_at = Column(DateTime, nullable=True)

    role = relationship("Role")
    invited_by = relationship("User")


def generate_invite_token() -> str:
    return secrets.token_urlsafe(32)
