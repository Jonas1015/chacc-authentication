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
from .tenant_access_service import GLOBAL_ADMIN_PRIVILEGES, user_privilege_names

_SyncSessionLocal = sessionmaker(bind=engine)


def can_access_restaurant(user: Any, restaurant: Any) -> bool:
    """Registered as the "can_access_restaurant" cross-plugin service."""
    user_id = getattr(user, "id", None)
    restaurant_uuid = getattr(restaurant, "uuid", None)
    if user_id is None or restaurant_uuid is None:
        return False

    db = _SyncSessionLocal()
    try:
        privilege_names = user_privilege_names(db, user_id)
        if privilege_names & GLOBAL_ADMIN_PRIVILEGES:
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
