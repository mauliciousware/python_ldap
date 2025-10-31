"""
Role-Based Access Control

This module defines user roles and their permissions:
- Organizational Admin (OA): Manages organization-wide settings
- Domain Admin (DA): Manages domain-specific operations
- Regular User: Basic access
"""

from enum import Enum
from typing import List, Set, Optional
from .permissions import Permissions


class UserRole(Enum):
    """User role enumeration."""
    USER = "user"
    DOMAIN_ADMIN = "domain_admin"
    ORGANIZATIONAL_ADMIN = "organizational_admin"


class BaseRole:
    """Base class for all roles."""
    
    def __init__(self, username: str, role: UserRole):
        """
        Initialize a role.
        
        Args:
            username: Username
            role: User role
        """
        self.username = username
        self.role = role
        self.permissions: Set[Permissions] = set()
    
    def has_permission(self, permission: Permissions) -> bool:
        """Check if role has a specific permission."""
        return permission in self.permissions
    
    def get_permissions(self) -> Set[Permissions]:
        """Get all permissions for this role."""
        return self.permissions.copy()


class OrganizationalAdmin(BaseRole):
    """
    Organizational Admin (OA) role.
    
    OAs have full control over the organization, including:
    - Creating/managing all users
    - Creating/managing domain admins
    - Managing CA certificates
    - Configuring organization-wide settings
    """
    
    def __init__(self, username: str):
        """
        Initialize Organizational Admin.
        
        Args:
            username: Username of the OA
        """
        super().__init__(username, UserRole.ORGANIZATIONAL_ADMIN)
        
        # OA has all permissions
        self.permissions = {
            Permissions.CREATE_USER,
            Permissions.DELETE_USER,
            Permissions.MODIFY_USER,
            Permissions.VIEW_USER,
            Permissions.CREATE_DOMAIN_ADMIN,
            Permissions.DELETE_DOMAIN_ADMIN,
            Permissions.ISSUE_CERTIFICATE,
            Permissions.REVOKE_CERTIFICATE,
            Permissions.VIEW_CERTIFICATE,
            Permissions.MODIFY_DIRECTORY,
            Permissions.VIEW_DIRECTORY,
            Permissions.MANAGE_ORGANIZATION,
            Permissions.CONFIGURE_SERVER,
        }
    
    def create_domain_admin(self, username: str, domain: str) -> 'DomainAdmin':
        """
        Create a new domain admin.
        
        Args:
            username: Username for the new domain admin
            domain: Domain name
            
        Returns:
            DomainAdmin instance
        """
        return DomainAdmin(username, domain)
    
    def manage_organization(self) -> dict:
        """
        Get organization management information.
        
        Returns:
            Dictionary with organization stats
        """
        return {
            "role": "Organizational Admin",
            "username": self.username,
            "permissions": [p.value for p in self.permissions]
        }


class DomainAdmin(BaseRole):
    """
    Domain Admin (DA) role.
    
    DAs manage operations within their domain:
    - Creating/managing users in their domain
    - Issuing certificates for their domain
    - Viewing domain-specific directory entries
    """
    
    def __init__(self, username: str, domain: str):
        """
        Initialize Domain Admin.
        
        Args:
            username: Username of the DA
            domain: Domain name the DA manages
        """
        super().__init__(username, UserRole.DOMAIN_ADMIN)
        self.domain = domain
        
        # DA has domain-specific permissions
        self.permissions = {
            Permissions.CREATE_USER,
            Permissions.DELETE_USER,
            Permissions.MODIFY_USER,
            Permissions.VIEW_USER,
            Permissions.ISSUE_CERTIFICATE,
            Permissions.VIEW_CERTIFICATE,
            Permissions.MODIFY_DIRECTORY,
            Permissions.VIEW_DIRECTORY,
        }
    
    def get_domain(self) -> str:
        """Get the domain this DA manages."""
        return self.domain
    
    def manage_domain(self) -> dict:
        """
        Get domain management information.
        
        Returns:
            Dictionary with domain stats
        """
        return {
            "role": "Domain Admin",
            "username": self.username,
            "domain": self.domain,
            "permissions": [p.value for p in self.permissions]
        }


class RegularUser(BaseRole):
    """
    Regular user role.
    
    Regular users have basic permissions:
    - View their own information
    - Request certificates
    - Modify their own password
    """
    
    def __init__(self, username: str):
        """
        Initialize regular user.
        
        Args:
            username: Username
        """
        super().__init__(username, UserRole.USER)
        
        self.permissions = {
            Permissions.VIEW_USER,
            Permissions.REQUEST_CERTIFICATE,
            Permissions.VIEW_CERTIFICATE,
        }

