"""
Tenant-scoped (per-restaurant) staff-management authorization for Epic C7.

A caller may create invites / revoke access for a given restaurant_uuid if:
  - they hold a global privilege (ALL or MANAGE_SYSTEM), via RBACService, OR
  - they hold a RestaurantAccess grant for that exact restaurant whose Role
    carries the MANAGE_MENU privilege (a Menu Manager for restaurant X).
"""

from typing import Optional

from sqlalchemy.orm import Session

from ..models.tenant_access import RestaurantAccess
from .rbac_service import RBACService

GLOBAL_STAFF_ADMIN_PRIVILEGES = ["ALL", "MANAGE_SYSTEM"]
TENANT_STAFF_MANAGER_PRIVILEGE = "MANAGE_MENU"


async def get_restaurant_access(
    db: Session, user_id: int, restaurant_uuid: str
) -> Optional[RestaurantAccess]:
    """Look up a user's tenant access grant for one restaurant (or None)."""
    return (
        db.query(RestaurantAccess)
        .filter(
            RestaurantAccess.user_id == user_id,
            RestaurantAccess.restaurant_uuid == restaurant_uuid,
        )
        .first()
    )


async def user_can_manage_restaurant_staff(
    db: Session, rbac: RBACService, user_id: int, restaurant_uuid: str
) -> bool:
    """True if user_id may create invites / revoke access for restaurant_uuid."""
    if await rbac.has_any_privilege(user_id, GLOBAL_STAFF_ADMIN_PRIVILEGES):
        return True

    access = await get_restaurant_access(db, user_id, restaurant_uuid)
    if access is None or access.role is None:
        return False

    role_privilege_names = {p.name for p in access.role.privileges}
    return (
        TENANT_STAFF_MANAGER_PRIVILEGE in role_privilege_names
        or "ALL" in role_privilege_names
    )
