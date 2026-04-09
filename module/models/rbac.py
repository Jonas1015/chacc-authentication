"""
RBAC (Role-Based Access Control) models for authentication module.

This module provides:
- Privilege: Individual permissions (VERB_NOUN format)
- Role: Collection of privileges
- RoleGroup: Collection of roles
- UserRole: User to Role association
- RolePrivilege: Role to Privilege association
- UserPrivilege: Direct privilege assignment to user

Inherits from ChaCCBaseModel which provides:
- id: Integer primary key
- uuid: UUID (unique, indexed)

When enable_audit_fields is True, additional fields are added:
- created_at, updated_at, deleted_at (DateTime)
- created_by_id, updated_by_id, deleted_by_id (Foreign keys to users)
"""
from chacc_api import ChaCCBaseModel, register_model
from sqlalchemy import Column, String, Integer, ForeignKey, Boolean, Table, UniqueConstraint
from sqlalchemy.orm import relationship


# Association table for Role-Privilege many-to-many
role_privilege_association = Table(
    'role_privileges',
    ChaCCBaseModel.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('privilege_id', Integer, ForeignKey('privileges.id'), primary_key=True)
)


# Association table for User-Privilege many-to-many (direct assignments)
user_privilege_association = Table(
    'user_privileges',
    ChaCCBaseModel.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('privilege_id', Integer, ForeignKey('privileges.id'), primary_key=True)
)


# Association table for User-Role many-to-many
user_role_association = Table(
    'user_roles',
    ChaCCBaseModel.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)


# Association table for RoleGroup-Role many-to-many
role_group_role_association = Table(
    'role_group_roles',
    ChaCCBaseModel.metadata,
    Column('role_group_id', Integer, ForeignKey('role_groups.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)


@register_model
class Privilege(ChaCCBaseModel):
    """
    Privilege model - Individual permission in VERB_NOUN format.
    
    Examples:
    - READ_OWN_PROFILE
    - WRITE_USERS
    - MANAGE_SYSTEM
    - ALL (super-user privilege)
    
    Severity levels:
    - CRITICAL: System-breaking or security-compromising
    - VERY HIGH: High-impact administrative operations
    - HIGH: Significant data access or modification
    - MEDIUM: Limited data access or minor modifications
    - LOW: Minimal impact, basic read operations
    """
    __tablename__ = "privileges"
    
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # CRITICAL, VERY HIGH, HIGH, MEDIUM, LOW
    
    # Relationships
    roles = relationship("Role", secondary=role_privilege_association, back_populates="privileges")
    direct_users = relationship("User", secondary=user_privilege_association, back_populates="direct_privileges")


@register_model
class Role(ChaCCBaseModel):
    """
    Role model - Collection of privileges that can be assigned to users.
    
    Roles can be organized into RoleGroups for easier management.
    """
    __tablename__ = "roles"
    
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=False)
    is_system = Column(Boolean, default=False, nullable=False)  # System roles cannot be deleted
    
    # Relationships
    privileges = relationship("Privilege", secondary=role_privilege_association, back_populates="roles")
    role_groups = relationship("RoleGroup", secondary=role_group_role_association, back_populates="roles")
    users = relationship("User", secondary=user_role_association, back_populates="roles")


@register_model
class RoleGroup(ChaCCBaseModel):
    """
    RoleGroup model - Collection of roles for easier management.
    
    RoleGroups allow organizing roles into logical groupings.
    """
    __tablename__ = "role_groups"
    
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=False)
    
    # Relationships
    roles = relationship("Role", secondary=role_group_role_association, back_populates="role_groups")


# Default system privileges - must be created on first startup
DEFAULT_PRIVILEGES = [
    {"name": "ALL", "description": "Super user privilege that grants all access", "severity": "CRITICAL"},
    {"name": "READ_OWN_PROFILE", "description": "Read own user profile", "severity": "LOW"},
    {"name": "WRITE_OWN_PROFILE", "description": "Modify own user profile", "severity": "MEDIUM"},
    {"name": "READ_USERS", "description": "Read all user profiles", "severity": "MEDIUM"},
    {"name": "WRITE_USERS", "description": "Modify any user profile", "severity": "HIGH"},
    {"name": "READ_ROLES", "description": "Read roles and assignments", "severity": "MEDIUM"},
    {"name": "WRITE_ROLES", "description": "Create/modify roles", "severity": "HIGH"},
    {"name": "READ_PRIVILEGES", "description": "Read privileges", "severity": "MEDIUM"},
    {"name": "WRITE_PRIVILEGES", "description": "Create/modify privileges", "severity": "VERY HIGH"},
    {"name": "MANAGE_SYSTEM", "description": "Full administrative access", "severity": "CRITICAL"},
    {"name": "READ_ROLE_GROUPS", "description": "Read role groups", "severity": "MEDIUM"},
    {"name": "WRITE_ROLE_GROUPS", "description": "Create/modify role groups", "severity": "HIGH"},
    {"name": "WRITE_USER_ROLES", "description": "Assign roles to users", "severity": "HIGH"},
    {"name": "WRITE_USER_PRIVILEGES", "description": "Assign direct privileges to users", "severity": "HIGH"},
    {"name": "READ_USER_PRIVILEGES", "description": "View user's effective privileges", "severity": "MEDIUM"},
    {"name": "READ_PASSWORD_POLICY", "description": "View password policy", "severity": "MEDIUM"},
    {"name": "WRITE_PASSWORD_POLICY", "description": "Create/modify password policy", "severity": "HIGH"},
]


# Default system roles
DEFAULT_ROLES = [
    {
        "name": "ADMIN",
        "description": "Full system administrator with all privileges",
        "privilege_names": ["ALL", "MANAGE_SYSTEM"]
    },
    {
        "name": "USER",
        "description": "Standard user with basic profile access",
        "privilege_names": ["READ_OWN_PROFILE", "WRITE_OWN_PROFILE"]
    },
    {
        "name": "POWER_USER",
        "description": "Power user with extended privileges",
        "privilege_names": ["READ_OWN_PROFILE", "WRITE_OWN_PROFILE", "READ_USERS"]
    },
]
