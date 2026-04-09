"""
RBAC (Role-Based Access Control) Service with Graceful Redis Degradation.

This service provides:
- Privilege management (read, create, update, delete)
- Role management (create, assign privileges, assign to users)
- User privilege calculation (role privileges + direct privileges)
- Redis caching for high-performance privilege lookups
- Automatic cache invalidation on changes

The service follows the Hybrid DB/Redis pattern:
- Redis is used for high-speed privilege caching
- PostgreSQL is the ultimate source of truth
- If Redis is unavailable, the system seamlessly falls back to PostgreSQL
"""
import json
from typing import Optional, List

from sqlalchemy import select, and_, or_
from sqlalchemy.orm import Session
from src.logger import configure_logging

from ..models.rbac import Privilege, Role, RoleGroup, DEFAULT_PRIVILEGES, DEFAULT_ROLES
from ..models.user import User

logger = configure_logging()

# Cache TTL for user privileges (1 hour)
PRIVILEGE_CACHE_TTL = 3600


class RBACService:
    """
    RBAC Service with Hybrid DB/Redis Fallback.
    
    Redis is used as a fast cache layer for user privileges,
    but the DB always has the final say.
    """
    
    def __init__(self, db: Session, redis_client=None):
        self.db = db
        self.redis = redis_client
    
    def _get_redis_client(self):
        """Get Redis client if available."""
        return self.redis
    
    # ==================== Privilege Operations ====================
    
    async def get_privilege_by_name(self, name: str) -> Optional[Privilege]:
        """Get a privilege by name."""
        return self.db.query(Privilege).filter(Privilege.name == name).first()
    
    async def get_all_privileges(self) -> List[Privilege]:
        """Get all privileges."""
        return self.db.query(Privilege).all()
    
    async def create_privilege(
        self,
        name: str,
        description: str,
        severity: str
    ) -> Privilege:
        """Create a new privilege."""
        privilege = Privilege(
            name=name,
            description=description,
            severity=severity
        )
        self.db.add(privilege)
        self.db.commit()
        self.db.refresh(privilege)
        logger.info(f"Created privilege: {name}")
        return privilege
    
    # ==================== Role Operations ====================
    
    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Get a role by name."""
        return self.db.query(Role).filter(Role.name == name).first()
    
    async def get_all_roles(self) -> List[Role]:
        """Get all roles."""
        return self.db.query(Role).all()
    
    async def create_role(
        self,
        name: str,
        description: str,
        is_system: bool = False
    ) -> Role:
        """Create a new role."""
        role = Role(
            name=name,
            description=description,
            is_system=is_system
        )
        self.db.add(role)
        self.db.commit()
        self.db.refresh(role)
        logger.info(f"Created role: {name}")
        return role
    
    async def assign_privilege_to_role(
        self,
        role_name: str,
        privilege_name: str
    ) -> bool:
        """Assign a privilege to a role."""
        role = await self.get_role_by_name(role_name)
        privilege = await self.get_privilege_by_name(privilege_name)
        
        if not role or not privilege:
            return False
        
        if privilege not in role.privileges:
            role.privileges.append(privilege)
            self.db.commit()
            logger.info(f"Assigned privilege {privilege_name} to role {role_name}")
        
        # Invalidate cache for all users with this role
        await self._invalidate_all_user_cache()
        
        return True
    
    async def remove_privilege_from_role(
        self,
        role_name: str,
        privilege_name: str
    ) -> bool:
        """Remove a privilege from a role."""
        role = await self.get_role_by_name(role_name)
        privilege = await self.get_privilege_by_name(privilege_name)
        
        if not role or not privilege:
            return False
        
        if privilege in role.privileges:
            role.privileges.remove(privilege)
            self.db.commit()
            logger.info(f"Removed privilege {privilege_name} from role {role_name}")
        
        # Invalidate cache for all users with this role
        await self._invalidate_all_user_cache()
        
        return True
    
    # ==================== User Privilege Operations ====================
    
    async def get_user_privileges(self, user_id: int) -> List[str]:
        """
        Get effective privileges for a user.
        
        This includes:
        - Direct privileges assigned to the user
        - Privileges from roles assigned to the user
        - ALL privilege grants all access
        
        Uses Redis cache with graceful degradation to PostgreSQL.
        """
        cache_key = f"user_privileges:{user_id}"
        
        # 1. Try Cache
        redis_client = self._get_redis_client()
        if redis_client:
            try:
                cached = await redis_client.get(cache_key)
                if cached:
                    logger.debug(f"Cache hit for user {user_id} privileges")
                    return json.loads(cached)
            except Exception as e:
                logger.warning(f"Redis unavailable, falling back to DB for RBAC: {e}")
        
        # 2. Database Fallback (Calculate from roles + direct privileges)
        privileges = await self._calculate_effective_privileges_from_db(user_id)
        priv_names = [p.name for p in privileges]
        
        # 3. Try to Update Cache (1 hour TTL)
        if redis_client:
            try:
                await redis_client.setex(cache_key, PRIVILEGE_CACHE_TTL, json.dumps(priv_names))
            except Exception as e:
                logger.warning(f"Failed to cache privileges for user {user_id}: {e}")
        
        return priv_names
    
    async def _calculate_effective_privileges_from_db(self, user_id: int) -> List[Privilege]:
        """
        Calculate effective privileges from database.
        
        This includes:
        - Direct privileges assigned to the user
        - Privileges from all roles assigned to the user
        """
        # Get user with roles and direct privileges
        user = self.db.query(User).filter(User.id == user_id).first()
        
        if not user:
            return []
        
        # Collect privilege IDs from roles
        role_privilege_ids = set()
        for role in user.roles:
            for privilege in role.privileges:
                role_privilege_ids.add(privilege.id)
        
        # Collect direct privilege IDs
        direct_privilege_ids = {p.id for p in user.direct_privileges}
        
        # Combine all privilege IDs
        all_privilege_ids = role_privilege_ids.union(direct_privilege_ids)
        
        # Fetch all privileges
        if all_privilege_ids:
            privileges = self.db.query(Privilege).filter(
                Privilege.id.in_(all_privilege_ids)
            ).all()
        else:
            privileges = []
        
        return privileges
    
    async def assign_role_to_user(
        self,
        user_id: int,
        role_name: str
    ) -> bool:
        """Assign a role to a user."""
        user = self.db.query(User).filter(User.id == user_id).first()
        role = await self.get_role_by_name(role_name)
        
        if not user or not role:
            return False
        
        if role not in user.roles:
            user.roles.append(role)
            self.db.commit()
            logger.info(f"Assigned role {role_name} to user {user_id}")
        
        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)
        
        return True
    
    async def remove_role_from_user(
        self,
        user_id: int,
        role_name: str
    ) -> bool:
        """Remove a role from a user."""
        user = self.db.query(User).filter(User.id == user_id).first()
        role = await self.get_role_by_name(role_name)
        
        if not user or not role:
            return False
        
        if role in user.roles:
            user.roles.remove(role)
            self.db.commit()
            logger.info(f"Removed role {role_name} from user {user_id}")
        
        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)
        
        return True
    
    async def assign_direct_privilege_to_user(
        self,
        user_id: int,
        privilege_name: str
    ) -> bool:
        """Assign a direct privilege to a user."""
        user = self.db.query(User).filter(User.id == user_id).first()
        privilege = await self.get_privilege_by_name(privilege_name)
        
        if not user or not privilege:
            return False
        
        if privilege not in user.direct_privileges:
            user.direct_privileges.append(privilege)
            self.db.commit()
            logger.info(f"Assigned direct privilege {privilege_name} to user {user_id}")
        
        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)
        
        return True
    
    async def remove_direct_privilege_from_user(
        self,
        user_id: int,
        privilege_name: str
    ) -> bool:
        """Remove a direct privilege from a user."""
        user = self.db.query(User).filter(User.id == user_id).first()
        privilege = await self.get_privilege_by_name(privilege_name)
        
        if not user or not privilege:
            return False
        
        if privilege in user.direct_privileges:
            user.direct_privileges.remove(privilege)
            self.db.commit()
            logger.info(f"Removed direct privilege {privilege_name} from user {user_id}")
        
        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)
        
        return True
    
    async def invalidate_user_cache(self, user_id: int):
        """Invalidate a user's privilege cache."""
        cache_key = f"user_privileges:{user_id}"
        redis_client = self._get_redis_client()
        
        if redis_client:
            try:
                await redis_client.delete(cache_key)
                logger.debug(f"Invalidated cache for user {user_id}")
            except Exception as e:
                logger.warning(f"Failed to invalidate cache for user {user_id}: {e}")
    
    async def _invalidate_all_user_cache(self):
        """Invalidate all user privilege caches (use with caution)."""
        # This is expensive - in production, consider using cache tags or patterns
        redis_client = self._get_redis_client()
        
        if redis_client:
            try:
                # Get all keys matching user_privileges:*
                keys_to_delete = []
                async for key in redis_client.scan_iter(match="user_privileges:*"):
                    keys_to_delete.append(key)
                
                if keys_to_delete:
                    await redis_client.delete(*keys_to_delete)
                    logger.info(f"Invalidated {len(keys_to_delete)} user privilege caches")
            except Exception as e:
                logger.warning(f"Failed to invalidate all user caches: {e}")
    
    # ==================== Privilege Check ====================
    
    async def has_privilege(self, user_id: int, privilege_name: str) -> bool:
        """
        Check if a user has a specific privilege.
        
        Users with ALL privilege automatically have all privileges.
        """
        user_privs = await self.get_user_privileges(user_id)
        
        # Check for ALL privilege (super user)
        if "ALL" in user_privs:
            return True
        
        return privilege_name in user_privs
    
    async def has_any_privilege(self, user_id: int, privilege_names: List[str]) -> bool:
        """Check if a user has any of the specified privileges."""
        user_privs = await self.get_user_privileges(user_id)
        
        # Check for ALL privilege (super user)
        if "ALL" in user_privs:
            return True
        
        return any(p in user_privs for p in privilege_names)


def get_rbac_service(db: Session, redis_client=None) -> RBACService:
    """Create an RBACService instance."""
    return RBACService(db, redis_client)
