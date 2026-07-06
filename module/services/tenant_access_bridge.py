"""
Synchronous bridge consumed by the `menu` plugin's dormant
`can_access_restaurant` hook (menu_src/services/analytics_services.py,
`_user_can_access_restaurant`). That hook is called synchronously,
un-awaited, from a plain `def` service function - so this callable MUST be
plain sync, MUST NOT be `async def`, and must duck-type `restaurant` (never
import the menu plugin's Restaurant class, to preserve plugin isolation).

Because it cannot `await`, it cannot use context.get_db() (an async
generator) or RBACService (all-async). It opens its own synchronous session
via the shared engine re-exported by chacc_api, and re-implements the tiny
"does this user have ALL/MANAGE_SYSTEM, else do they have a RestaurantAccess
row for this restaurant" check with plain sync ORM queries.
"""

from typing import Any

from chacc_api import engine
from sqlalchemy.orm import sessionmaker

from ..models.tenant_access import RestaurantAccess
from ..models.user import User

_SyncSessionLocal = sessionmaker(bind=engine)

_GLOBAL_ADMIN_PRIVILEGES = {"ALL", "MANAGE_SYSTEM"}


def _sync_user_privilege_names(db, user_id: int) -> set:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return set()
    names = {p.name for p in user.direct_privileges}
    for role in user.roles:
        names.update(p.name for p in role.privileges)
    return names


def can_access_restaurant(user: Any, restaurant: Any) -> bool:
    """Registered as the "can_access_restaurant" cross-plugin service."""
    user_id = getattr(user, "id", None)
    restaurant_uuid = getattr(restaurant, "uuid", None)
    if user_id is None or restaurant_uuid is None:
        return False

    db = _SyncSessionLocal()
    try:
        privilege_names = _sync_user_privilege_names(db, user_id)
        if privilege_names & _GLOBAL_ADMIN_PRIVILEGES:
            return True

        access = (
            db.query(RestaurantAccess)
            .filter(
                RestaurantAccess.user_id == user_id,
                RestaurantAccess.restaurant_uuid == str(restaurant_uuid),
            )
            .first()
        )
        return access is not None
    finally:
        db.close()
