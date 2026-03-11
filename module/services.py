from sqlalchemy.orm import Session

from .auth import get_password_hash
from .models import User
import os
from .context_factory import get_module_context

async def create_default_user(context):
    """
    Create a default admin user if no users exist.
    Uses environment variables for configuration:
    - DEFAULT_ADMIN_USERNAME: Default admin username (default: "admin")
    - DEFAULT_ADMIN_PASSWORD: Default admin password (default: "admin123")
    """
    _module_context = context if context else get_module_context()
    
    default_username = _module_context.get_module_config("DEFAULT_ADMIN_USERNAME", "authentication", "admin")
    default_password = _module_context.get_module_config("DEFAULT_ADMIN_PASSWORD", "authentication", "admin123")
    
    db: Session = await anext(_module_context.get_db())
    
    user_count = db.query(User).count()
    if user_count > 0:
        _module_context.logger.info(f"Users already exist ({user_count}), skipping default user creation")
        return
    
    hashed_password = get_password_hash(default_password)
    default_user = User(
        username=default_username,
        email=f"{default_username}@chacc.local",
        password_hash=hashed_password,
        is_active=True,
        role="admin"
    )
    
    db.add(default_user)
    db.commit()
    db.refresh(default_user)
    
    _module_context.logger.info(f"Created default admin user: {default_username}")
    _module_context.logger.warning(f"DEFAULT CREDENTIALS - Username: {default_username}, Password: {default_password}")
    _module_context.logger.warning("Please change the default password in production!")