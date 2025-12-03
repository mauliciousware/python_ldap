"""
Authentication and Authorization Module

This module provides role-based access control:
- Organizational Admin (OA) role
- Domain Admin (DA) role
- Permission management
- Secure communication
"""

from .roles import OrganizationalAdmin, DomainAdmin, RegularUser, UserRole, BaseRole
from .permissions import Permissions, PermissionChecker, RoleManager
from .secure_communication import SecureChannel, SecureHandshake

__all__ = [
    'OrganizationalAdmin', 'DomainAdmin', 'RegularUser', 'UserRole', 'BaseRole',
    'Permissions', 'PermissionChecker', 'RoleManager',
    'SecureChannel', 'SecureHandshake'
]

