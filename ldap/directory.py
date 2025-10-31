"""
LDAP-like Directory Service

This module implements a simplified LDAP directory service that stores
user and organizational data. It provides basic operations like add,
search, modify, and authenticate.
"""

from typing import Dict, List, Optional, Any
import hashlib
import base64


class DirectoryService:
    """
    Simplified LDAP-like directory service for storing user and organization data.
    Uses in-memory storage with a hierarchical structure.
    """
    
    def __init__(self, base_dn="dc=cs,dc=binghamton,dc=edu"):
        """
        Initialize the directory service.
        
        Args:
            base_dn: Base Distinguished Name for the directory
        """
        self.base_dn = base_dn
        self.entries: Dict[str, Dict[str, Any]] = {}
        self._initialize_base_structure()
    
    def _initialize_base_structure(self):
        """Initialize base directory structure."""
        # Create base entry
        self.entries[self.base_dn] = {
            "objectClass": ["top", "domain"],
            "dc": ["cs"],
            "dn": self.base_dn
        }
        
        # Create Certificates OU
        certs_dn = f"ou=Certificates,{self.base_dn}"
        self.entries[certs_dn] = {
            "objectClass": ["top", "organizationalUnit"],
            "ou": ["Certificates"],
            "dn": certs_dn
        }
        
        # Create Users OU
        users_dn = f"ou=Users,{self.base_dn}"
        self.entries[users_dn] = {
            "objectClass": ["top", "organizationalUnit"],
            "ou": ["Users"],
            "dn": users_dn
        }
    
    def add_user(self, username: str, attributes: Dict[str, Any], 
                 password: Optional[str] = None, ou: str = "Users") -> str:
        """
        Add a user to the directory.
        
        Args:
            username: Username (will be used as CN)
            attributes: Dictionary of user attributes
            password: Optional password (will be hashed)
            ou: Organizational unit (default: "Users")
            
        Returns:
            Distinguished Name (DN) of the created entry
        """
        ou_dn = f"ou={ou},{self.base_dn}"
        if ou_dn not in self.entries:
            raise ValueError(f"OU '{ou}' does not exist")
        
        dn = f"cn={username},{ou_dn}"
        
        if dn in self.entries:
            raise ValueError(f"User '{username}' already exists")
        
        entry = {
            "objectClass": ["top", "inetOrgPerson", "person"],
            "cn": [username],
            "dn": dn,
            **{k: [v] if not isinstance(v, list) else v for k, v in attributes.items()}
        }
        
        if password:
            entry["userPassword"] = [self._hash_password(password)]
        
        self.entries[dn] = entry
        return dn
    
    def add_certificate_entry(self, common_name: str, certificate_data: bytes,
                             attributes: Optional[Dict[str, Any]] = None) -> str:
        """
        Add a certificate entry to the directory.
        
        Args:
            common_name: Common name for the certificate
            certificate_data: Certificate data in DER format
            attributes: Optional additional attributes
            
        Returns:
            Distinguished Name (DN) of the created entry
        """
        certs_dn = f"ou=Certificates,{self.base_dn}"
        dn = f"cn={common_name},{certs_dn}"
        
        if dn in self.entries:
            raise ValueError(f"Certificate entry '{common_name}' already exists")
        
        entry = {
            "objectClass": ["top", "inetOrgPerson", "pkiUser"],
            "cn": [common_name],
            "sn": [common_name.split(".")[0] if "." in common_name else common_name],
            "uid": [common_name],
            "dn": dn,
            "userCertificate;binary": [certificate_data]
        }
        
        if attributes:
            for k, v in attributes.items():
                entry[k] = [v] if not isinstance(v, list) else v
        
        self.entries[dn] = entry
        return dn
    
    def search(self, base_dn: Optional[str] = None, 
              filter_attrs: Optional[Dict[str, Any]] = None,
              scope: str = "sub") -> List[Dict[str, Any]]:
        """
        Search the directory.
        
        Args:
            base_dn: Base DN to search from (default: root)
            filter_attrs: Dictionary of attribute filters
            scope: Search scope ("base", "one", "sub")
            
        Returns:
            List of matching entries
        """
        if base_dn is None:
            base_dn = self.base_dn
        
        results = []
        
        for dn, entry in self.entries.items():
            # Check scope
            if scope == "base" and dn != base_dn:
                continue
            elif scope == "one" and not dn.endswith(f",{base_dn}"):
                continue
            elif scope == "sub" and not (dn == base_dn or dn.endswith(f",{base_dn}")):
                continue
            
            # Apply filters
            if filter_attrs:
                match = True
                for attr, value in filter_attrs.items():
                    if attr not in entry:
                        match = False
                        break
                    entry_values = entry[attr]
                    if isinstance(value, str):
                        if value not in entry_values:
                            match = False
                            break
                    elif isinstance(value, list):
                        if not any(v in entry_values for v in value):
                            match = False
                            break
                
                if not match:
                    continue
            
            results.append(entry.copy())
        
        return results
    
    def search_by_cn(self, common_name: str, ou: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Search for an entry by common name.
        
        Args:
            common_name: Common name to search for
            ou: Optional organizational unit to limit search
            
        Returns:
            Entry dictionary or None if not found
        """
        filter_attrs = {"cn": common_name}
        base_dn = f"ou={ou},{self.base_dn}" if ou else self.base_dn
        
        results = self.search(base_dn=base_dn, filter_attrs=filter_attrs)
        return results[0] if results else None
    
    def modify(self, dn: str, changes: Dict[str, Any], operation: str = "replace") -> bool:
        """
        Modify an entry in the directory.
        
        Args:
            dn: Distinguished Name of the entry
            changes: Dictionary of attributes to change
            operation: Operation type ("add", "replace", "delete")
            
        Returns:
            True if successful
        """
        if dn not in self.entries:
            raise ValueError(f"Entry '{dn}' not found")
        
        entry = self.entries[dn]
        
        for attr, value in changes.items():
            if operation == "add":
                if attr not in entry:
                    entry[attr] = []
                if isinstance(value, list):
                    entry[attr].extend(value)
                else:
                    entry[attr].append(value)
            elif operation == "replace":
                entry[attr] = [value] if not isinstance(value, list) else value
            elif operation == "delete":
                if attr in entry:
                    if isinstance(value, list):
                        for v in value:
                            if v in entry[attr]:
                                entry[attr].remove(v)
                    else:
                        if value in entry[attr]:
                            entry[attr].remove(value)
                    if not entry[attr]:
                        del entry[attr]
        
        return True
    
    def delete(self, dn: str) -> bool:
        """
        Delete an entry from the directory.
        
        Args:
            dn: Distinguished Name of the entry
            
        Returns:
            True if successful
        """
        if dn not in self.entries:
            raise ValueError(f"Entry '{dn}' not found")
        
        # Don't allow deletion of base structure
        if dn == self.base_dn or dn.startswith("ou="):
            raise ValueError("Cannot delete base structure entries")
        
        del self.entries[dn]
        return True
    
    def authenticate(self, dn: str, password: str) -> bool:
        """
        Authenticate a user with password.
        
        Args:
            dn: Distinguished Name of the user
            password: Password to verify
            
        Returns:
            True if authentication successful
        """
        if dn not in self.entries:
            return False
        
        entry = self.entries[dn]
        if "userPassword" not in entry:
            return False
        
        hashed_password = self._hash_password(password)
        return hashed_password in entry["userPassword"]
    
    def get_certificate(self, common_name: str) -> Optional[bytes]:
        """
        Get certificate data for a common name.
        
        Args:
            common_name: Common name to search for
            
        Returns:
            Certificate data in DER format or None
        """
        entry = self.search_by_cn(common_name, ou="Certificates")
        if entry and "userCertificate;binary" in entry:
            cert_data = entry["userCertificate;binary"]
            return cert_data[0] if isinstance(cert_data, list) else cert_data
        return None
    
    def _hash_password(self, password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def list_all_entries(self, ou: Optional[str] = None) -> List[str]:
        """
        List all entry DNs.
        
        Args:
            ou: Optional OU to filter by
            
        Returns:
            List of Distinguished Names
        """
        if ou:
            ou_dn = f"ou={ou},{self.base_dn}"
            return [dn for dn in self.entries.keys() if dn.endswith(f",{ou_dn}") or dn == ou_dn]
        return list(self.entries.keys())

