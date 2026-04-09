"""
RBAC Routes for privilege and role management.

This module provides API endpoints for:
- Privilege management (CRUD)
- Role management (CRUD)
- User role assignment
- User direct privilege assignment
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from chacc_api import BackboneContext
from pydantic import BaseModel

from .auth import get_current_user
from .context_factory import get_module_context
from .models import User, Privilege, Role, RoleGroup
from .services import get_rbac_service
from .dependencies import get_redis_client


router = APIRouter(prefix="/rbac")


# Pydantic models for request/response
class PrivilegeResponse(BaseModel):
    id: int
    name: str
    description: str
    severity: str
    
    class Config:
        from_attributes = True


class RoleResponse(BaseModel):
    id: int
    name: str
    description: str
    is_system: bool
    
    class Config:
        from_attributes = True


class RoleWithPrivilegesResponse(BaseModel):
    id: int
    name: str
    description: str
    is_system: bool
    privileges: List[PrivilegeResponse]
    
    class Config:
        from_attributes = True


class UserPrivilegesResponse(BaseModel):
    user_id: int
    privileges: List[str]


class PrivilegeCreate(BaseModel):
    name: str
    description: str
    severity: str  # CRITICAL, VERY HIGH, HIGH, MEDIUM, LOW


class RoleCreate(BaseModel):
    name: str
    description: str


class AssignPrivilegeRequest(BaseModel):
    privilege_name: str


class AssignRoleRequest(BaseModel):
    role_name: str


# Helper to get DB
async def get_db():
    """Get database session from module context."""
    context = get_module_context()
    if context is None:
        raise HTTPException(status_code=500, detail="Module not initialized")
    return await context.get_db().__anext__()


# ==================== Privilege Endpoints ====================

@router.get("/privileges", response_model=List[PrivilegeResponse])
async def get_privileges(
    current_user: User = Depends(get_current_user),
):
    """Get all privileges."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    privileges = await rbac.get_all_privileges()
    return privileges


@router.post("/privileges", response_model=PrivilegeResponse)
async def create_privilege(
    privilege: PrivilegeCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new privilege."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_PRIVILEGES"
        )
    
    # Check if privilege already exists
    existing = await rbac.get_privilege_by_name(privilege.name)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Privilege '{privilege.name}' already exists"
        )
    
    new_privilege = await rbac.create_privilege(
        name=privilege.name,
        description=privilege.description,
        severity=privilege.severity
    )
    
    return new_privilege


# ==================== Role Endpoints ====================

@router.get("/roles", response_model=List[RoleResponse])
async def get_roles(
    current_user: User = Depends(get_current_user),
):
    """Get all roles."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    roles = await rbac.get_all_roles()
    return roles


@router.get("/roles/{role_name}", response_model=RoleWithPrivilegesResponse)
async def get_role(
    role_name: str,
    current_user: User = Depends(get_current_user),
):
    """Get a specific role with its privileges."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    role = await rbac.get_role_by_name(role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    return role


@router.post("/roles", response_model=RoleResponse)
async def create_role(
    role: RoleCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new role."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES"
        )
    
    # Check if role already exists
    existing = await rbac.get_role_by_name(role.name)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Role '{role.name}' already exists"
        )
    
    new_role = await rbac.create_role(
        name=role.name,
        description=role.description
    )
    
    return new_role


@router.put("/roles/{role_name}/privileges")
async def assign_privilege_to_role(
    role_name: str,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user),
):
    """Assign a privilege to a role."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES"
        )
    
    success = await rbac.assign_privilege_to_role(role_name, request.privilege_name)
    if not success:
        raise HTTPException(status_code=404, detail="Role or privilege not found")
    
    return {"message": f"Privilege '{request.privilege_name}' assigned to role '{role_name}'"}


@router.delete("/roles/{role_name}/privileges")
async def remove_privilege_from_role(
    role_name: str,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user),
):
    """Remove a privilege from a role."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES"
        )
    
    success = await rbac.remove_privilege_from_role(role_name, request.privilege_name)
    if not success:
        raise HTTPException(status_code=404, detail="Role or privilege not found")
    
    return {"message": f"Privilege '{request.privilege_name}' removed from role '{role_name}'"}


# ==================== User Privilege Endpoints ====================

@router.get("/users/{user_id}/privileges", response_model=UserPrivilegesResponse)
async def get_user_privileges(
    user_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get effective privileges for a user."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission to view
    if not await rbac.has_privilege(current_user.id, "READ_USER_PRIVILEGES"):
        # Users can only view their own privileges
        if current_user.id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing required privilege: READ_USER_PRIVILEGES"
            )
    
    privileges = await rbac.get_user_privileges(user_id)
    
    return UserPrivilegesResponse(user_id=user_id, privileges=privileges)


@router.put("/users/{user_id}/roles")
async def assign_role_to_user(
    user_id: int,
    request: AssignRoleRequest,
    current_user: User = Depends(get_current_user),
):
    """Assign a role to a user."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_USER_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_ROLES"
        )
    
    success = await rbac.assign_role_to_user(user_id, request.role_name)
    if not success:
        raise HTTPException(status_code=404, detail="User or role not found")
    
    return {"message": f"Role '{request.role_name}' assigned to user {user_id}"}


@router.delete("/users/{user_id}/roles")
async def remove_role_from_user(
    user_id: int,
    request: AssignRoleRequest,
    current_user: User = Depends(get_current_user),
):
    """Remove a role from a user."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_USER_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_ROLES"
        )
    
    success = await rbac.remove_role_from_user(user_id, request.role_name)
    if not success:
        raise HTTPException(status_code=404, detail="User or role not found")
    
    return {"message": f"Role '{request.role_name}' removed from user {user_id}"}


@router.put("/users/{user_id}/privileges")
async def assign_direct_privilege_to_user(
    user_id: int,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user),
):
    """Assign a direct privilege to a user."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_USER_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_PRIVILEGES"
        )
    
    success = await rbac.assign_direct_privilege_to_user(user_id, request.privilege_name)
    if not success:
        raise HTTPException(status_code=404, detail="User or privilege not found")
    
    return {"message": f"Direct privilege '{request.privilege_name}' assigned to user {user_id}"}


@router.delete("/users/{user_id}/privileges")
async def remove_direct_privilege_from_user(
    user_id: int,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user),
):
    """Remove a direct privilege from a user."""
    db = await get_db()
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    
    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_USER_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_PRIVILEGES"
        )
    
    success = await rbac.remove_direct_privilege_from_user(user_id, request.privilege_name)
    if not success:
        raise HTTPException(status_code=404, detail="User or privilege not found")
    
    return {"message": f"Direct privilege '{request.privilege_name}' removed from user {user_id}"}


# ==================== Role Group Endpoints ====================

@router.get("/role-groups", response_model=list)
async def get_role_groups(
    current_user: User = Depends(get_current_user),
):
    """Get all role groups."""
    db = await get_db()
    role_groups = db.query(RoleGroup).all()
    return role_groups
