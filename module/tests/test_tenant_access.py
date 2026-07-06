"""
Tests for the synchronous `can_access_restaurant` bridge consumed by the
`menu` plugin's dormant cross-plugin authorization hook (Epic C7).
"""

import types

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ..auth import get_password_hash
from ..models import User
from ..models.rbac import (
    Privilege,
    Role,
    role_privilege_association,
    user_privilege_association,
    user_role_association,
)
from ..models.tenant_access import RestaurantAccess
from ..services import tenant_access_bridge

TABLES = [
    Privilege.__table__,
    Role.__table__,
    role_privilege_association,
    User.__table__,
    user_role_association,
    user_privilege_association,
    RestaurantAccess.__table__,
]


def _restaurant(uuid_str):
    return types.SimpleNamespace(uuid=uuid_str, id=1)


@pytest.fixture
def db_session(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    for table in TABLES:
        table.create(engine, checkfirst=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Point the bridge's module-level sessionmaker at our test engine instead
    # of the real production engine it binds to at import time.
    monkeypatch.setattr(tenant_access_bridge, "_SyncSessionLocal", SessionLocal)

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_global_admin_always_true(db_session):
    admin_role = Role(name="ADMIN", description="admin", is_system=True)
    all_priv = Privilege(name="ALL", description="all", severity="CRITICAL")
    db_session.add_all([admin_role, all_priv])
    db_session.flush()
    admin_role.privileges.append(all_priv)
    admin = User(
        username="a", email="a@example.com", password_hash=get_password_hash("pw")
    )
    db_session.add(admin)
    db_session.flush()
    admin.roles.append(admin_role)
    db_session.commit()

    assert tenant_access_bridge.can_access_restaurant(admin, _restaurant("rest-1")) is True
    assert tenant_access_bridge.can_access_restaurant(admin, _restaurant("rest-999")) is True


def test_tenant_grant_holder_scoped_to_their_restaurant(db_session):
    role = Role(name="ANALYTICS_VIEWER", description="viewer", is_system=True)
    db_session.add(role)
    db_session.flush()
    user = User(
        username="v", email="v@example.com", password_hash=get_password_hash("pw")
    )
    db_session.add(user)
    db_session.flush()
    db_session.add(
        RestaurantAccess(user_id=user.id, restaurant_uuid="rest-1", role_id=role.id)
    )
    db_session.commit()

    assert tenant_access_bridge.can_access_restaurant(user, _restaurant("rest-1")) is True
    assert tenant_access_bridge.can_access_restaurant(user, _restaurant("rest-2")) is False


def test_no_grant_at_all_is_false(db_session):
    user = User(
        username="nobody",
        email="n@example.com",
        password_hash=get_password_hash("pw"),
    )
    db_session.add(user)
    db_session.commit()

    assert tenant_access_bridge.can_access_restaurant(user, _restaurant("rest-1")) is False


def test_unknown_user_or_restaurant_is_false(db_session):
    assert tenant_access_bridge.can_access_restaurant(None, _restaurant("rest-1")) is False
    user = User(
        username="x", email="x@example.com", password_hash=get_password_hash("pw")
    )
    db_session.add(user)
    db_session.commit()
    assert tenant_access_bridge.can_access_restaurant(user, types.SimpleNamespace(id=1)) is False


def test_revoke_removes_access(db_session):
    role = Role(name="MENU_MANAGER", description="mgr", is_system=True)
    db_session.add(role)
    db_session.flush()
    user = User(
        username="m", email="m@example.com", password_hash=get_password_hash("pw")
    )
    db_session.add(user)
    db_session.flush()
    grant = RestaurantAccess(user_id=user.id, restaurant_uuid="rest-1", role_id=role.id)
    db_session.add(grant)
    db_session.commit()

    assert tenant_access_bridge.can_access_restaurant(user, _restaurant("rest-1")) is True

    db_session.delete(grant)
    db_session.commit()

    assert tenant_access_bridge.can_access_restaurant(user, _restaurant("rest-1")) is False
