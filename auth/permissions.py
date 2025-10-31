"""
Permission Management

This module defines permissions and permission checking utilities.
"""

from enum import Enum
from typing import Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .roles import BaseRole


class Permissions(Enum):
    """Permission enumeration."""
    # User management
    CREATE_USER = "create_user"
    DELETE_USER = "delete_user"
    MODIFY_USER = "modify_user"
    VIEW_USER = "view_user"
    
    # Admin management
    CREATE_DOMAIN_ADMIN = "create_domain_admin"
    DELETE_DOMAIN_ADMIN = "delete_domain_admin"
    
    # Certificate management
    ISSUE_CERTIFICATE = "issue_certificate"
    REVOKE_CERTIFICATE = "revoke_certificate"
    VIEW_CERTIFICATE = "view_certificate"
    REQUEST_CERTIFICATE = "request_certificate"
    
    # Directory management
    MODIFY_DIRECTORY = "modify_directory"
    VIEW_DIRECTORY = "view_directory"
    
    # Organization management
    MANAGE_ORGANIZATION = "manage_organization"
    
    # Server configuration
    CONFIGURE_SERVER = "configure_server"


class PermissionChecker:
    """
    Utility class for checking permissions.
    """
    
    @staticmethod
    def check_permission(role: 'BaseRole', permission: Permissions) -> bool:
        """
        Check if a role has a specific permission.
        
        Args:
            role: Role instance
            permission: Permission to check
            
        Returns:
            True if role has permission
        """
        return role.has_permission(permission)
    
    @staticmethod
    def require_permission(role: 'BaseRole', permission: Permissions):
        """
        Require a permission, raise exception if not present.
        
        Args:
            role: Role instance
            permission: Required permission
            
        Raises:
            PermissionError: If role doesn't have permission
        """
        if not role.has_permission(permission):
            raise PermissionError(
                f"Role '{role.role.value}' does not have permission '{permission.value}'"
            )
    
    @staticmethod
    def check_multiple_permissions(role: 'BaseRole', permissions: Set[Permissions],
                                  require_all: bool = True) -> bool:
        """
        Check multiple permissions.
        
        Args:
            role: Role instance
            permissions: Set of permissions to check
            require_all: If True, all permissions must be present
        
        Returns:
            True if requirements are met
        """
        if require_all:
            return all(role.has_permission(p) for p in permissions)
        else:
            return any(role.has_permission(p) for p in permissions)
    
    @staticmethod
    def get_missing_permissions(role: 'BaseRole', permissions: Set[Permissions]) -> Set[Permissions]:
        """
        Get permissions that are missing from a role.
        
        Args:
            role: Role instance
            permissions: Set of permissions to check
            
        Returns:
            Set of missing permissions
        """
        return permissions - role.get_permissions()


class RoleManager:
    """
    Manager for roles and permissions.
    """
    
    def __init__(self):
        """Initialize role manager."""
        self.roles: dict = {}
    
    def add_role(self, role: 'BaseRole'):
        """
        Add a role to the manager.
        
        Args:
            role: Role instance
        """
        self.roles[role.username] = role
    
    def get_role(self, username: str) -> 'BaseRole':
        """
        Get role for a username.
        
        Args:
            username: Username
            
        Returns:
            Role instance
            
        Raises:
            ValueError: If role not found
        """
        if username not in self.roles:
            raise ValueError(f"Role for user '{username}' not found")
        return self.roles[username]
    
    def has_permission(self, username: str, permission: Permissions) -> bool:
        """
        Check if user has permission.
        
        Args:
            username: Username
            permission: Permission to check
            
        Returns:
            True if user has permission
        """
        if username not in self.roles:
            return False
        return self.roles[username].has_permission(permission)

