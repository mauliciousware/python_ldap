"""
LDAP Client

This module provides client-side LDAP operations.
"""

from typing import Dict, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from server.ldap_server import LDAPServer

from auth.roles import BaseRole


class LDAPClient:
    """
    LDAP client that communicates with the LDAP server.
    """
    
    def __init__(self, server, user_role: BaseRole):
        """
        Initialize LDAP client.
        
        Args:
            server: LDAP server instance
            user_role: User role for permission checking
        """
        self.server = server
        self.user_role = user_role
    
    def add_user(self, username: str, attributes: Dict[str, Any],
                password: Optional[str] = None) -> Dict[str, Any]:
        """Add a user via the server."""
        return self.server.handle_request(
            "add_user",
            self.user_role,
            username=username,
            attributes=attributes,
            password=password
        )
    
    def search(self, base_dn: Optional[str] = None,
              filter_attrs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Search the directory via the server."""
        return self.server.handle_request(
            "search",
            self.user_role,
            base_dn=base_dn,
            filter_attrs=filter_attrs
        )
    
    def modify(self, dn: str, changes: Dict[str, Any],
              operation: str = "replace") -> Dict[str, Any]:
        """Modify an entry via the server."""
        return self.server.handle_request(
            "modify",
            self.user_role,
            dn=dn,
            changes=changes,
            operation=operation
        )
    
    def delete(self, dn: str) -> Dict[str, Any]:
        """Delete an entry via the server."""
        return self.server.handle_request(
            "delete",
            self.user_role,
            dn=dn
        )
    
    def authenticate(self, dn: str, password: str) -> Dict[str, Any]:
        """Authenticate via the server."""
        return self.server.handle_request(
            "authenticate",
            self.user_role,
            dn=dn,
            password=password
        )

