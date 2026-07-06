"""
Tenant-scoped (per-restaurant) staff-management authorization for Epic C7.

A caller may create invites / revoke access for a given restaurant_uuid if:
  - they hold a global privilege (ALL or MANAGE_SYSTEM), via RBACService, OR
  - they hold a RestaurantAccess grant for that exact restaurant whose Role
    carries the MANAGE_MENU privilege (a Menu Manager for restaurant X).
"""

from typing import List, Optional

from sqlalchemy.orm import Session

from ..context_factory import get_module_context
from ..models.rbac import Role
from ..models.tenant_access import RestaurantAccess
from ..models.user import User
from .rbac_service import RBACService

GLOBAL_STAFF_ADMIN_PRIVILEGES = ["ALL", "MANAGE_SYSTEM"]
TENANT_STAFF_MANAGER_PRIVILEGE = "MANAGE_MENU"

# Shared with services/tenant_access_bridge.py, which needs the identical
# "does this user have a global admin privilege" computation but via a
# synchronous, cache-free session (see that module's docstring for why).
GLOBAL_ADMIN_PRIVILEGES = {"ALL", "MANAGE_SYSTEM"}


def user_privilege_names(db: Session, user_id: int) -> set:
    """All privilege names effective for a user: direct + via global roles."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return set()
    names = {p.name for p in user.direct_privileges}
    for role in user.roles:
        names.update(p.name for p in role.privileges)
    return names


def is_global_admin(db: Session, user_id: int) -> bool:
    return bool(user_privilege_names(db, user_id) & GLOBAL_ADMIN_PRIVILEGES)


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


async def get_accessible_restaurant_uuids(user_id: int) -> Optional[List[str]]:
    """
    Restaurant UUIDs the given user may see/manage.

    Returns None to mean "unrestricted" (global admin - caller should apply
    no filter), or a (possibly empty) list of restaurant_uuid strings for a
    tenant-scoped user. Opens its own DB session via this plugin's own
    context, since callers (e.g. the `menu` plugin) only pass a user_id, not
    a Session from their own module.
    """
    context = get_module_context()
    db = await anext(context.get_db())

    if is_global_admin(db, user_id):
        return None

    grants = db.query(RestaurantAccess).filter(RestaurantAccess.user_id == user_id).all()
    return [grant.restaurant_uuid for grant in grants]


async def grant_restaurant_access(
    user_id: int, restaurant_uuid: str, role_name: str = "MENU_MANAGER"
) -> None:
    """
    Grant a user tenant access to a restaurant, e.g. auto-granted to the
    creator of a new restaurant so they aren't locked out of managing it.
    No-ops if the role is unknown or a grant already exists (idempotent).
    """
    context = get_module_context()
    db = await anext(context.get_db())

    role = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        context.logger.warning(
            f"grant_restaurant_access: role '{role_name}' not found, skipping grant"
        )
        return

    existing = await get_restaurant_access(db, user_id, restaurant_uuid)
    if existing:
        return

    db.add(
        RestaurantAccess(
            user_id=user_id, restaurant_uuid=restaurant_uuid, role_id=role.id
        )
    )
    db.commit()
