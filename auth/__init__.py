"""
Authentication and Authorization Module

This module provides role-based access control:
- Organizational Admin (OA) role
- Domain Admin (DA) role
- Permission management
- Secure communication
"""

from .roles import OrganizationalAdmin, DomainAdmin, UserRole
from .permissions import Permissions, PermissionChecker
from .secure_communication import SecureChannel, SecureHandshake

__all__ = ['OrganizationalAdmin', 'DomainAdmin', 'UserRole', 'Permissions', 'PermissionChecker', 
           'SecureChannel', 'SecureHandshake']

