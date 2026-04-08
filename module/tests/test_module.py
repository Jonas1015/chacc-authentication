
"""
Unit tests for authentication module.
"""
import pytest
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from module.auth import get_password_hash, verify_password, authenticate_user, create_access_token
from module.models import User, UserCreate


@pytest.fixture
def db_session():
    """Database session fixture for testing."""
    # Create in-memory SQLite database for testing
    engine = create_engine("sqlite:///:memory:")
    # Create tables for our models
    User.__table__.create(engine, checkfirst=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        User.__table__.drop(engine, checkfirst=True)


def test_password_hashing():
    """Test password hashing and verification."""
    password = "testpassword"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed)
    assert not verify_password("wrongpassword", hashed)


def test_create_access_token():
    """Test JWT token creation."""
    data = {"sub": "testuser"}
    token = create_access_token(data)
    assert isinstance(token, str)
    assert len(token) > 0


def test_authenticate_user(db_session: Session):
    """Test user authentication."""
    # Create a test user
    password = "testpass"
    hashed = get_password_hash(password)
    user = User(username="testuser", email="test@example.com", password_hash=hashed)
    db_session.add(user)
    db_session.commit()

    # Test successful authentication
    auth_user = authenticate_user(db_session, "testuser", password)
    assert auth_user is not False
    assert auth_user.username == "testuser"

    # Test failed authentication
    auth_user = authenticate_user(db_session, "testuser", "wrongpass")
    assert auth_user is False

    # Test non-existent user
    auth_user = authenticate_user(db_session, "nonexistent", password)
    assert auth_user is False


def test_user_model():
    """Test User model creation."""
    user = User(username="test", email="test@example.com", password_hash="hash")
    assert user.username == "test"
    assert user.email == "test@example.com"
    assert user.is_active is True


def test_user_create_model():
    """Test UserCreate Pydantic model."""
    user_data = UserCreate(username="test", email="test@example.com", password="pass")
    assert user_data.username == "test"
    assert user_data.email == "test@example.com"
    assert user_data.password == "pass"


def test_authentication_module_info():
    """Test module information retrieval."""
    from ..main import get_plugin_info

    info = get_plugin_info()
    assert info["name"] == "authentication"
    assert info["version"] == "0.1.0"
    assert "status" in info


async def run_module_tests():
    """
    Run all module tests.
    This function is called by the ChaCC backbone when the module is loaded.
    """
    import sys
    import os

    # Add the module directory to Python path for testing
    module_dir = os.path.dirname(os.path.dirname(__file__))
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)

    try:
        # Run pytest programmatically
        import subprocess
        result = subprocess.run([
            sys.executable, "-m", "pytest",
            __file__,  # Run this test file
            "-v", "--tb=short", "--no-header"
        ], capture_output=True, text=True, cwd=os.path.dirname(__file__))

        if result.returncode == 0:
            print(f"✓ All authentication tests passed")
            return {"status": "passed", "message": f"All authentication tests passed"}
        else:
            print(f"✗ authentication tests failed")
            if result.stdout:
                print("Test output:")
                print(result.stdout)
            if result.stderr:
                print("Errors:")
                print(result.stderr)
            return {
                "status": "failed",
                "message": f"authentication tests failed",
                "details": result.stdout + result.stderr
            }

    except Exception as e:
        print(f"✗ Error running authentication tests: {e}")
        return {
            "status": "error",
            "message": f"Error running authentication tests: {e}"
        }
