from fastapi import APIRouter
from src.core_services import BackboneContext
from typing import Optional
from .auth import get_current_user
from .routes import router as auth_router
from .context_factory import get_context, set_module_context

# --- Module Setup ---
def setup_plugin(context: Optional[BackboneContext] = None):
    """
    This function is called by the ChaCC API backbone to initialize your module.
    It can also be called in development mode without a context.
    """
    _module_context = get_context(context)
    set_module_context(_module_context)  

    _module_context.logger.info("authentication: Setup initiated!")

    # Register services
    _module_context.register_service("get_current_user", get_current_user)

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
