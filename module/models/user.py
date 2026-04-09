"""
User model for authentication module.

This model inherits from ChaCCBaseModel which provides:
- id: Integer primary key
- uuid: UUID (unique, indexed)

When enable_audit_fields is True (configured in backbone), additional fields are added:
- created_at, updated_at, deleted_at (DateTime)
- created_by_id, updated_by_id, deleted_by_id (Foreign keys to users)
"""
from chacc_api import ChaCCBaseModel, register_model
from sqlalchemy import Column, String, Boolean
from sqlalchemy.orm import relationship


# Import association tables from rbac module
from .rbac import user_role_association, user_privilege_association


@register_model
class User(ChaCCBaseModel):
    """
    User model for authentication.
    
    Inherits ChaCCBaseModel for:
    - id (primary key)
    - uuid (UUID, unique, indexed)
    
    Additional audit fields are dynamically added by the backbone
    when enable_audit_fields is configured.
    """
    __tablename__ = "users"
    
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # RBAC Relationships - Many-to-many through association tables
    roles = relationship(
        "Role",
        secondary=user_role_association,
        back_populates="users"
    )
    direct_privileges = relationship(
        "Privilege",
        secondary=user_privilege_association,
        back_populates="direct_users"
    )
