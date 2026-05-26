"""
RBAC Dependencies for route protection.

This module provides FastAPI dependencies for privilege-based route protection:
- require_privilege: Require a specific privilege to access a route
- require_any_privilege: Require any of the specified privileges

The dependencies integrate with the RBACService for privilege checking
and support the Hybrid DB/Redis pattern for high performance.
"""

from typing import List

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from .auth import get_current_user
from .context_factory import get_db, get_module_context
from .models import User
from .services import get_rbac_service


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
        current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
    ):
        redis_client = await get_redis_client()

        rbac = get_rbac_service(db, redis_client)

        user_privs = await rbac.get_user_privileges(current_user.id)

        if "ALL" in user_privs or privilege_name in user_privs:
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required privilege: {privilege_name}",
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
        current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
    ):
        redis_client = await get_redis_client()

        rbac = get_rbac_service(db, redis_client)

        has_access = await rbac.has_any_privilege(current_user.id, privilege_names)

        if has_access:
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required privileges. You need at least one of: {', '.join(privilege_names)}",
        )

    return privilege_checker


async def get_user_privileges(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> List[str]:
    """
    Dependency to get current user's effective privileges.

    Usage:
        @router.get("/my-permissions")
        async def get_my_permissions(privs: List[str] = Depends(get_user_privileges)):
            return {"privileges": privs}
    """
    redis_client = await get_redis_client()

    rbac = get_rbac_service(db, redis_client)

    return await rbac.get_user_privileges(current_user.id)
