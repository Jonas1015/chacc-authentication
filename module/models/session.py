"""
OAuth Session model for authentication module.

This model is the database source of truth for OAuth2 refresh token rotation.
Redis is used as a fast cache layer, but the DB always has the final say.

Inherits from ChaCCBaseModel which provides:
- id: Integer primary key
- uuid: UUID (unique, indexed)

When enable_audit_fields is True, additional fields are added:
- created_at, updated_at, deleted_at (DateTime)
- created_by_id, updated_by_id, deleted_by_id (Foreign keys to users)
"""
from chacc_api import ChaCCBaseModel, register_model
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship


@register_model
class OAuthSession(ChaCCBaseModel):
    """
    OAuth2 Session model for refresh token management.
    
    This is the database source of truth for rotating refresh tokens.
    Redis acts as a lightning-fast cache layer, but the DB always has the final say.
    
    Inherits ChaCCBaseModel for:
    - id (primary key)
    - uuid (UUID, unique, indexed)
    """
    __tablename__ = "oauth_sessions"
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    family_id = Column(String, nullable=False, index=True)
    refresh_token_id = Column(String, unique=True, nullable=False, index=True)
    
    is_rotated = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    device_info = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    
    user = relationship("User", backref="oauth_sessions")
