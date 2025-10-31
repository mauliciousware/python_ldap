"""
User Manager

This module provides user management utilities for the directory service.
"""

from typing import Dict, Optional
from .directory import DirectoryService


class UserManager:
    """
    User management utilities for the directory service.
    """
    
    def __init__(self, directory: DirectoryService):
        """
        Initialize UserManager with a directory service.
        
        Args:
            directory: DirectoryService instance
        """
        self.directory = directory
    
    def create_user(self, username: str, email: str, password: str,
                   full_name: Optional[str] = None, **extra_attrs) -> str:
        """
        Create a new user in the directory.
        
        Args:
            username: Username (will be used as CN)
            email: User email address
            password: User password
            full_name: Full name (optional)
            **extra_attrs: Additional attributes
            
        Returns:
            Distinguished Name of the created user
        """
        attributes = {
            "mail": email,
            **extra_attrs
        }
        
        if full_name:
            attributes["displayName"] = full_name
        
        return self.directory.add_user(username, attributes, password)
    
    def update_user(self, username: str, **updates) -> bool:
        """
        Update user attributes.
        
        Args:
            username: Username to update
            **updates: Attributes to update
            
        Returns:
            True if successful
        """
        user = self.directory.search_by_cn(username, ou="Users")
        if not user:
            raise ValueError(f"User '{username}' not found")
        
        return self.directory.modify(user["dn"], updates)
    
    def change_password(self, username: str, new_password: str) -> bool:
        """
        Change a user's password.
        
        Args:
            username: Username
            new_password: New password
            
        Returns:
            True if successful
        """
        user = self.directory.search_by_cn(username, ou="Users")
        if not user:
            raise ValueError(f"User '{username}' not found")
        
        hashed_password = self.directory._hash_password(new_password)
        return self.directory.modify(user["dn"], {"userPassword": hashed_password})
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Get user information.
        
        Args:
            username: Username to look up
            
        Returns:
            User entry dictionary or None
        """
        return self.directory.search_by_cn(username, ou="Users")
    
    def list_users(self) -> list:
        """
        List all users in the directory.
        
        Returns:
            List of usernames
        """
        users = self.directory.search(base_dn=f"ou=Users,{self.directory.base_dn}",
                                     filter_attrs={"objectClass": "inetOrgPerson"})
        return [user["cn"][0] for user in users if "cn" in user]
    
    def delete_user(self, username: str) -> bool:
        """
        Delete a user from the directory.
        
        Args:
            username: Username to delete
            
        Returns:
            True if successful
        """
        user = self.directory.search_by_cn(username, ou="Users")
        if not user:
            raise ValueError(f"User '{username}' not found")
        
        return self.directory.delete(user["dn"])

