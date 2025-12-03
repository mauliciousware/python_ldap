"""
User Manager

This module provides user management utilities for the directory service.
Certificate issuance is integrated with user creation via CA.
"""

from typing import Dict, Optional, Tuple, Any
from .directory import DirectoryService


class UserManager:
    """
    User management utilities for the directory service.
    Supports automatic certificate issuance during user creation.
    """
    
    def __init__(self, directory: DirectoryService, ca: Optional[Any] = None):
        """
        Initialize UserManager with a directory service.
        
        Args:
            directory: DirectoryService instance
            ca: CertificateAuthority instance (optional, required for certificate issuance)
        """
        self.directory = directory
        self.ca = ca
    
    def create_user(self, username: str, email: str, password: str,
                   full_name: Optional[str] = None, 
                   issue_certificate: bool = True,
                   **extra_attrs) -> Tuple[str, Optional[Dict[str, str]]]:
        """
        Create a new user in the directory and optionally issue a certificate via CA.
        
        Args:
            username: Username (will be used as CN)
            email: User email address
            password: User password
            full_name: Full name (optional)
            issue_certificate: Whether to issue a certificate for the user (default: True)
            **extra_attrs: Additional attributes
            
        Returns:
            Tuple of (Distinguished Name, certificate_info dict or None)
            certificate_info contains: cert_pem, private_key_pem
        """
        attributes = {
            "mail": email,
            **extra_attrs
        }
        
        if full_name:
            attributes["displayName"] = full_name
        
        dn = self.directory.add_user(username, attributes, password)
        
        # Issue certificate via CA if available and requested
        cert_info = None
        if issue_certificate and self.ca:
            cert_info = self._issue_user_certificate(username)
        
        return dn, cert_info
    
    def _issue_user_certificate(self, username: str) -> Dict[str, str]:
        """
        Issue a certificate for a user via the Certificate Authority.
        
        Args:
            username: Username (Common Name for certificate)
            
        Returns:
            Dictionary with cert_pem and private_key_pem
        """
        from ca.cert_manager import CertificateManager
        
        # Generate CSR with private key
        csr_pem, _, private_key_pem = CertificateManager.generate_csr(username)
        
        # Sign the CSR with the CA
        cert_pem, _ = self.ca.sign_csr(csr_pem, username, cert_type="client")
        
        # Store certificate in LDAP directory
        cert_der = CertificateManager.certificate_to_der(cert_pem)
        self.directory.add_certificate_entry(username, cert_der)
        
        print(f"   [CA] Certificate issued for user '{username}'")
        
        return {
            "cert_pem": cert_pem,
            "private_key_pem": private_key_pem
        }
    
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

