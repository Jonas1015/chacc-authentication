from .services import create_default_user
from chacc_api import BackboneContext
from typing import Optional
from .auth import get_current_user
from .routes import router as auth_router, registerRouter
from .routes_rbac import router as rbac_router
from .context_factory import get_context, set_module_context
from .models import DEFAULT_PRIVILEGES, DEFAULT_ROLES
from .services.rbac_service import get_rbac_service
from chacc_api import run_automatic_migration


async def initialize_rbac_defaults(module_context: BackboneContext):
    """
    Initialize default privileges and roles for RBAC.
    
    This function ensures that the default system privileges and roles
    are created on first startup if they don't exist.
    """
    try:
        try:
            await run_automatic_migration()
        except Exception as e:
            module_context.logger.warning(f"Migration attempt failed (tables may not exist yet): {e}")
        
        db_gen = module_context.get_db()
        db = await db_gen.__anext__()
        
        redis_service = module_context.get_service("redis")
        redis_client = None
        if redis_service:
            try:
                redis_client = await redis_service.get_client()
            except Exception:
                pass
        
        rbac = get_rbac_service(db, redis_client)
        
        for priv_data in DEFAULT_PRIVILEGES:
            try:
                existing = await rbac.get_privilege_by_name(priv_data["name"])
                if not existing:
                    await rbac.create_privilege(
                        name=priv_data["name"],
                        description=priv_data["description"],
                        severity=priv_data["severity"]
                    )
                    module_context.logger.info(f"Created default privilege: {priv_data['name']}")
            except Exception as e:
                module_context.logger.warning(f"Could not create privilege {priv_data['name']}: {e}")
        
        for role_data in DEFAULT_ROLES:
            try:
                existing_role = await rbac.get_role_by_name(role_data["name"])
                if not existing_role:
                    new_role = await rbac.create_role(
                        name=role_data["name"],
                        description=role_data["description"],
                        is_system=True
                    )
                    
                    for priv_name in role_data.get("privilege_names", []):
                        await rbac.assign_privilege_to_role(role_data["name"], priv_name)
                    
                    module_context.logger.info(f"Created default role: {role_data['name']}")
            except Exception as e:
                module_context.logger.warning(f"Could not create role {role_data['name']}: {e}")
        
        module_context.logger.info("RBAC defaults initialization completed")
    except Exception as e:
        module_context.logger.warning(f"RBAC defaults initialization skipped: {e}")


async def setup_plugin(context: Optional[BackboneContext] = None):
    """
    This function is called by the ChaCC API backbone to initialize your module.
    It can also be called in development mode without a context.
    """
    _module_context = get_context(context)
    set_module_context(_module_context)  

    _module_context.logger.info("authentication: Setup initiated!")

    _module_context.register_service("get_current_user", get_current_user)
    
    await create_default_user(_module_context)
    
    if _module_context.get_module_config("ENABLE_SELF_REGISTRATION", "authentication", default="false").lower() == "true":
        _module_context.logger.info("ChaCC-Authentication: Self-registration is enabled.")
        auth_router.include_router(registerRouter)

    await initialize_rbac_defaults(_module_context)
    
    auth_router.include_router(rbac_router)
    return auth_router; 

def get_plugin_info():
    """
    Provides essential information about this module to the ChaCC API backbone.
    """
    return {
        "name": "authentication",
        "display_name": "Authentication Module",
        "version": "0.1.0",
        "author": "Your Name/Organization",
        "description": "A new ChaCC API module for authentication functionality.",
        "status": "enabled"
    }
