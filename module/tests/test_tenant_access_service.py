"""
Tests for the async tenant-access services used across plugin boundaries:
`get_accessible_restaurant_uuids` (restaurant list filtering) and
`grant_restaurant_access` (auto-grant on restaurant creation).
"""

from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ..auth import get_password_hash
from ..context_factory import set_module_context
from ..models import User
from ..models.rbac import (
    Privilege,
    Role,
    role_privilege_association,
    user_privilege_association,
    user_role_association,
)
from ..models.tenant_access import RestaurantAccess
from ..services.tenant_access_service import (
    get_accessible_restaurant_uuids,
    grant_restaurant_access,
)

TABLES = [
    Privilege.__table__,
    Role.__table__,
    role_privilege_association,
    User.__table__,
    user_role_association,
    user_privilege_association,
    RestaurantAccess.__table__,
]


class ServiceTestContext:
    def __init__(self, db_session):
        self.logger = Mock()
        self._db_session = db_session

    def get_module_config(self, key, module, default=None):
        return default

    def get_db(self):
        async def gen():
            yield self._db_session

        return gen()


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in TABLES:
        table.create(engine, checkfirst=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def ctx(db_session):
    context = ServiceTestContext(db_session)
    set_module_context(context)
    yield context
    set_module_context(None)


def _make_role(db, name, privilege_names):
    role = Role(name=name, description=name, is_system=True)
    db.add(role)
    db.flush()
    for pname in privilege_names:
        priv = Privilege(name=pname, description=pname, severity="HIGH")
        db.add(priv)
        db.flush()
        role.privileges.append(priv)
    db.commit()
    return role


def _make_user(db, username, role=None):
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=get_password_hash("pw"),
    )
    db.add(user)
    db.flush()
    if role:
        user.roles.append(role)
    db.commit()
    db.refresh(user)
    return user


@pytest.mark.asyncio
async def test_get_accessible_restaurant_uuids_none_for_global_admin(ctx, db_session):
    admin_role = _make_role(db_session, "ADMIN", ["ALL"])
    admin = _make_user(db_session, "admin1", admin_role)

    result = await get_accessible_restaurant_uuids(admin.id)
    assert result is None


@pytest.mark.asyncio
async def test_get_accessible_restaurant_uuids_lists_grants_for_tenant_user(ctx, db_session):
    manager_role = _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    user = _make_user(db_session, "manager1")
    db_session.add(
        RestaurantAccess(user_id=user.id, restaurant_uuid="rest-1", role_id=manager_role.id)
    )
    db_session.add(
        RestaurantAccess(user_id=user.id, restaurant_uuid="rest-2", role_id=manager_role.id)
    )
    db_session.commit()

    result = await get_accessible_restaurant_uuids(user.id)
    assert sorted(result) == ["rest-1", "rest-2"]


@pytest.mark.asyncio
async def test_get_accessible_restaurant_uuids_empty_for_user_with_no_grants(ctx, db_session):
    user = _make_user(db_session, "nobody")
    result = await get_accessible_restaurant_uuids(user.id)
    assert result == []


@pytest.mark.asyncio
async def test_grant_restaurant_access_creates_grant(ctx, db_session):
    _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    user = _make_user(db_session, "creator1")

    await grant_restaurant_access(user.id, "rest-9", "MENU_MANAGER")

    access = (
        db_session.query(RestaurantAccess)
        .filter(RestaurantAccess.user_id == user.id, RestaurantAccess.restaurant_uuid == "rest-9")
        .first()
    )
    assert access is not None


@pytest.mark.asyncio
async def test_grant_restaurant_access_is_idempotent(ctx, db_session):
    _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    user = _make_user(db_session, "creator2")

    await grant_restaurant_access(user.id, "rest-10", "MENU_MANAGER")
    await grant_restaurant_access(user.id, "rest-10", "MENU_MANAGER")

    count = (
        db_session.query(RestaurantAccess)
        .filter(RestaurantAccess.user_id == user.id, RestaurantAccess.restaurant_uuid == "rest-10")
        .count()
    )
    assert count == 1


@pytest.mark.asyncio
async def test_grant_restaurant_access_skips_unknown_role(ctx, db_session):
    user = _make_user(db_session, "creator3")

    await grant_restaurant_access(user.id, "rest-11", "NOT_A_ROLE")

    access = (
        db_session.query(RestaurantAccess)
        .filter(RestaurantAccess.user_id == user.id, RestaurantAccess.restaurant_uuid == "rest-11")
        .first()
    )
    assert access is None
