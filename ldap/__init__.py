"""
LDAP-like Directory Service Module

This module provides directory service functionality:
- User and organization data storage
- Search, add, modify, delete operations
- Authentication support
"""

from .directory import DirectoryService
from .user_manager import UserManager

__all__ = ['DirectoryService', 'UserManager']

