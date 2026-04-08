from .services import create_default_user
from chacc_api import BackboneContext
from typing import Optional
from .auth import get_current_user
from .routes import router as auth_router, registerRouter
from .context_factory import get_context, set_module_context

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

    return auth_router

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
