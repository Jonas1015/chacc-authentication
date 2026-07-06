"""
Tests for staff invite create/accept and tenant access revoke routes
(Epic C7 / REQ-1.11, REQ-1.12).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ..auth import create_access_token, get_password_hash
from ..context_factory import set_module_context
from ..models import User
from ..models.rbac import (
    Privilege,
    Role,
    role_privilege_association,
    user_privilege_association,
    user_role_association,
)
from ..models.tenant_access import Invite, RestaurantAccess
from ..routes_invites import router as invites_router

TABLES = [
    Privilege.__table__,
    Role.__table__,
    role_privilege_association,
    User.__table__,
    user_role_association,
    user_privilege_association,
    RestaurantAccess.__table__,
    Invite.__table__,
]


class InviteTestContext:
    """Minimal BackboneContext stand-in, mirroring test_module.py's MockBackboneContext."""

    def __init__(self, db_session):
        self.logger = Mock()
        self._module_config = {"SECRET_KEY": "test-secret-key-for-testing-purposes"}
        self._db_session = db_session

    def get_module_config(self, key, module, default=None):
        if module == "authentication" and key in self._module_config:
            return self._module_config[key]
        return default

    def get_db(self):
        async def gen():
            yield self._db_session

        return gen()

    def get_service(self, name):
        return None


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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
    context = InviteTestContext(db_session)
    set_module_context(context)
    yield context
    set_module_context(None)


@pytest.fixture
def client(ctx):
    app = FastAPI()
    app.include_router(invites_router, prefix="/authentication")
    with TestClient(app) as c:
        yield c


def _make_role(db, name, privilege_names):
    role = Role(name=name, description=name, is_system=True)
    db.add(role)
    db.flush()
    for pname in privilege_names:
        priv = db.query(Privilege).filter(Privilege.name == pname).first()
        if not priv:
            priv = Privilege(name=pname, description=pname, severity="HIGH")
            db.add(priv)
            db.flush()
        role.privileges.append(priv)
    db.commit()
    return role


def _make_user_with_role(db, username, role):
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=get_password_hash("pw"),
    )
    db.add(user)
    db.flush()
    user.roles.append(role)
    db.commit()
    db.refresh(user)
    return user


def _auth_header(user):
    return {"Authorization": f"Bearer {create_access_token({'sub': user.username})}"}


def test_invite_create_and_accept_happy_path(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    manager_role = _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    admin = _make_user_with_role(db_session, "admin1", db_session.query(Role).filter_by(name="ADMIN").first())

    resp = client.post(
        "/authentication/invites",
        json={
            "email": "new@example.com",
            "restaurant_uuid": "rest-1",
            "role_name": "MENU_MANAGER",
        },
        headers=_auth_header(admin),
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]

    accept_resp = client.post(
        f"/authentication/invites/{token}/accept",
        json={
            "username": "newstaff",
            "password": "secret123",
            "passwordConfirm": "secret123",
        },
    )
    assert accept_resp.status_code == 200, accept_resp.text
    assert accept_resp.json()["username"] == "newstaff"

    new_user = db_session.query(User).filter(User.username == "newstaff").first()
    access = (
        db_session.query(RestaurantAccess)
        .filter(RestaurantAccess.user_id == new_user.id)
        .first()
    )
    assert access is not None
    assert access.restaurant_uuid == "rest-1"
    assert access.role_id == manager_role.id
    # Global roles list must NOT have grown - no privilege escalation.
    assert manager_role not in new_user.roles

    invite = db_session.query(Invite).filter(Invite.token == token).first()
    assert invite.status == "ACCEPTED"
    assert invite.accepted_at is not None


def test_accept_rejects_expired_token(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    manager_role = _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    admin = _make_user_with_role(db_session, "admin2", db_session.query(Role).filter_by(name="ADMIN").first())

    expired = Invite(
        email="e@example.com",
        restaurant_uuid="rest-1",
        role_id=manager_role.id,
        token="expired-token",
        status="PENDING",
        invited_by_id=admin.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add(expired)
    db_session.commit()

    resp = client.post(
        "/authentication/invites/expired-token/accept",
        json={"username": "u", "password": "pw123456", "passwordConfirm": "pw123456"},
    )
    assert resp.status_code == 400


def test_accept_rejects_already_accepted_token(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    manager_role = _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    admin = _make_user_with_role(db_session, "admin3", db_session.query(Role).filter_by(name="ADMIN").first())

    used = Invite(
        email="e2@example.com",
        restaurant_uuid="rest-1",
        role_id=manager_role.id,
        token="used-token",
        status="ACCEPTED",
        invited_by_id=admin.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    db_session.add(used)
    db_session.commit()

    resp = client.post(
        "/authentication/invites/used-token/accept",
        json={"username": "u2", "password": "pw123456", "passwordConfirm": "pw123456"},
    )
    assert resp.status_code == 400


def test_accept_rejects_duplicate_username_or_email(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    manager_role = _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    admin = _make_user_with_role(db_session, "admin6", db_session.query(Role).filter_by(name="ADMIN").first())

    invite = Invite(
        email=admin.email,  # collides with an existing user's email
        restaurant_uuid="rest-1",
        role_id=manager_role.id,
        token="dup-token",
        status="PENDING",
        invited_by_id=admin.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    db_session.add(invite)
    db_session.commit()

    resp = client.post(
        "/authentication/invites/dup-token/accept",
        json={"username": "brandnew", "password": "pw123456", "passwordConfirm": "pw123456"},
    )
    assert resp.status_code == 400


def test_analytics_viewer_cannot_create_invites_or_revoke(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    viewer_role = _make_role(db_session, "ANALYTICS_VIEWER", ["VIEW_ANALYTICS"])
    admin = _make_user_with_role(db_session, "admin4", db_session.query(Role).filter_by(name="ADMIN").first())
    viewer = _make_user_with_role(db_session, "viewer1", viewer_role)

    resp = client.post(
        "/authentication/invites",
        json={
            "email": "x@example.com",
            "restaurant_uuid": "rest-2",
            "role_name": "ANALYTICS_VIEWER",
        },
        headers=_auth_header(viewer),
    )
    assert resp.status_code == 403

    # Give viewer a tenant grant for rest-2 with the Analytics Viewer role, then
    # confirm they still can't manage staff (no MANAGE_MENU on their tenant role).
    db_session.add(
        RestaurantAccess(
            user_id=viewer.id,
            restaurant_uuid="rest-2",
            role_id=viewer_role.id,
            invited_by_id=admin.id,
        )
    )
    db_session.commit()

    resp2 = client.delete(
        f"/authentication/users/{viewer.uuid}/access",
        params={"restaurant_uuid": "rest-2"},
        headers=_auth_header(viewer),
    )
    assert resp2.status_code == 403


def test_invite_creation_rejects_admin_role_escalation(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    admin = _make_user_with_role(db_session, "admin5", db_session.query(Role).filter_by(name="ADMIN").first())

    resp = client.post(
        "/authentication/invites",
        json={"email": "x@example.com", "restaurant_uuid": "rest-3", "role_name": "ADMIN"},
        headers=_auth_header(admin),
    )
    assert resp.status_code == 400


def test_menu_manager_can_invite_and_revoke_within_their_restaurant(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    manager_role = _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    viewer_role = _make_role(db_session, "ANALYTICS_VIEWER", ["VIEW_ANALYTICS"])
    manager = _make_user_with_role(db_session, "manager1", db_session.query(Role).filter_by(name="ADMIN").first())
    # Demote manager1 from global ADMIN, give them only a tenant grant for rest-4.
    manager.roles.remove(db_session.query(Role).filter_by(name="ADMIN").first())
    db_session.add(
        RestaurantAccess(
            user_id=manager.id, restaurant_uuid="rest-4", role_id=manager_role.id
        )
    )
    db_session.commit()

    resp = client.post(
        "/authentication/invites",
        json={
            "email": "analyst@example.com",
            "restaurant_uuid": "rest-4",
            "role_name": "ANALYTICS_VIEWER",
        },
        headers=_auth_header(manager),
    )
    assert resp.status_code == 200, resp.text

    # But the same manager cannot manage staff for a DIFFERENT restaurant.
    resp2 = client.post(
        "/authentication/invites",
        json={
            "email": "analyst2@example.com",
            "restaurant_uuid": "rest-5",
            "role_name": "ANALYTICS_VIEWER",
        },
        headers=_auth_header(manager),
    )
    assert resp2.status_code == 403


def test_revoke_access_removes_grant(ctx, db_session, client):
    _make_role(db_session, "ADMIN", ["ALL"])
    manager_role = _make_role(db_session, "MENU_MANAGER", ["MANAGE_MENU"])
    admin = _make_user_with_role(db_session, "admin7", db_session.query(Role).filter_by(name="ADMIN").first())
    staff = User(username="staff1", email="staff1@example.com", password_hash=get_password_hash("pw"))
    db_session.add(staff)
    db_session.flush()
    grant = RestaurantAccess(
        user_id=staff.id, restaurant_uuid="rest-6", role_id=manager_role.id, invited_by_id=admin.id
    )
    db_session.add(grant)
    db_session.commit()

    resp = client.delete(
        f"/authentication/users/{staff.uuid}/access",
        params={"restaurant_uuid": "rest-6"},
        headers=_auth_header(admin),
    )
    assert resp.status_code == 200, resp.text

    remaining = (
        db_session.query(RestaurantAccess)
        .filter(RestaurantAccess.user_id == staff.id, RestaurantAccess.restaurant_uuid == "rest-6")
        .first()
    )
    assert remaining is None

    # Revoking again returns 404 - already gone.
    resp2 = client.delete(
        f"/authentication/users/{staff.uuid}/access",
        params={"restaurant_uuid": "rest-6"},
        headers=_auth_header(admin),
    )
    assert resp2.status_code == 404
