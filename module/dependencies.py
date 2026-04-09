"""
RBAC Dependencies for route protection.

This module provides FastAPI dependencies for privilege-based route protection:
- require_privilege: Require a specific privilege to access a route
- require_any_privilege: Require any of the specified privileges

The dependencies integrate with the RBACService for privilege checking
and support the Hybrid DB/Redis pattern for high performance.
"""
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from chacc_api import BackboneContext

from .auth import get_current_user
from .context_factory import get_module_context
from .models import User
from .services import RBACService, get_rbac_service


async def get_redis_client():
    """Get Redis client from module context."""
    context = get_module_context()
    if context is None:
        return None
    
    redis_service = context.get_service("redis")
    if redis_service is None:
        return None
    
    try:
        return await redis_service.get_client()
    except Exception:
        return None


def require_privilege(privilege_name: str):
    """
    Dependency factory for protecting routes by privilege.
    
    Usage:
        @router.get("/users")
        @require_privilege("READ_USERS")
        async def get_users(current_user: User = Depends(get_current_user)):
            ...
    
    The ALL privilege grants access to all protected routes.
    """
    async def privilege_checker(
        current_user: User = Depends(get_current_user),
    ):
        # Get database session
        context = get_module_context()
        if context is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Module not initialized"
            )
        
        db = await anext(context.get_db())
        
        # Get Redis client
        redis_client = await get_redis_client()
        
        # Create RBAC service
        rbac = get_rbac_service(db, redis_client)
        
        # Check privilege
        user_privs = await rbac.get_user_privileges(current_user.id)
        
        # Check for ALL privilege (super user) or specific required privilege
        if "ALL" in user_privs or privilege_name in user_privs:
            return current_user
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required privilege: {privilege_name}"
        )
    
    return privilege_checker


def require_any_privilege(privilege_names: List[str]):
    """
    Dependency factory for protecting routes by any of the specified privileges.
    
    Usage:
        @router.get("/admin-panel")
        @require_any_privilege(["MANAGE_SYSTEM", "WRITE_USERS"])
        async def get_admin_panel(current_user: User = Depends(get_current_user)):
            ...
    
    The ALL privilege grants access to all protected routes.
    """
    async def privilege_checker(
        current_user: User = Depends(get_current_user),
    ):
        # Get database session
        context = get_module_context()
        if context is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Module not initialized"
            )
        
        db = await anext(context.get_db())
        
        # Get Redis client
        redis_client = await get_redis_client()
        
        # Create RBAC service
        rbac = get_rbac_service(db, redis_client)
        
        # Check privilege
        has_access = await rbac.has_any_privilege(current_user.id, privilege_names)
        
        if has_access:
            return current_user
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required privileges. You need at least one of: {', '.join(privilege_names)}"
        )
    
    return privilege_checker


async def get_user_privileges(
    current_user: User = Depends(get_current_user),
) -> List[str]:
    """
    Dependency to get current user's effective privileges.
    
    Usage:
        @router.get("/my-permissions")
        async def get_my_permissions(privs: List[str] = Depends(get_user_privileges)):
            return {"privileges": privs}
    """
    # Get database session
    context = get_module_context()
    if context is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Module not initialized"
        )
    
    db = await anext(context.get_db())
    
    # Get Redis client
    redis_client = await get_redis_client()
    
    # Create RBAC service
    rbac = get_rbac_service(db, redis_client)
    
    # Get privileges
    return await rbac.get_user_privileges(current_user.id)
