# LDAP-like Directory Service Module Documentation

## Purpose

The LDAP module provides a simplified directory service that stores user and organizational data. It mimics basic LDAP functionality without requiring an external LDAP server.

## Key Components

### DirectoryService Class

The main directory service that stores entries in a hierarchical structure.

**Key Functions:**

- `add_user()`: Add a new user to the directory
- `add_certificate_entry()`: Add a certificate entry to the directory
- `search()`: Search for entries with filters
- `search_by_cn()`: Search for an entry by common name
- `modify()`: Modify entry attributes
- `delete()`: Delete an entry
- `authenticate()`: Authenticate a user with password
- `get_certificate()`: Retrieve certificate data by common name

### UserManager Class

Utility class for managing users in the directory.

**Key Functions:**

- `create_user()`: Create a new user with attributes
- `update_user()`: Update user attributes
- `change_password()`: Change user password
- `get_user_info()`: Get user information
- `list_users()`: List all users
- `delete_user()`: Delete a user

## Example Usage

```python
from ldap.directory import DirectoryService
from ldap.user_manager import UserManager

# Initialize directory service
directory = DirectoryService()

# Create user manager
user_mgr = UserManager(directory)

# Create a user
user_mgr.create_user(
    username="john.doe",
    email="john@example.com",
    password="secret123",
    full_name="John Doe"
)

# Search for users
users = directory.search(
    base_dn="ou=Users,dc=cs,dc=binghamton,dc=edu",
    filter_attrs={"mail": "john@example.com"}
)

# Authenticate user
is_valid = directory.authenticate(
    "cn=john.doe,ou=Users,dc=cs,dc=binghamton,dc=edu",
    "secret123"
)

# Add certificate entry
directory.add_certificate_entry(
    common_name="server.example.com",
    certificate_data=cert_der_bytes
)
```

## Directory Structure

The directory uses a hierarchical structure:

```
dc=cs,dc=binghamton,dc=edu
├── ou=Certificates
│   └── cn=server.example.com
├── ou=Users
│   └── cn=john.doe
```

## How It Connects to the System

The LDAP module is used by:

1. **CA Module**: Certificate entries are stored in the directory
2. **Server Module**: Server looks up certificates from the directory
3. **Client Module**: Client can search for users and certificates
4. **Auth Module**: User authentication uses the directory

## Storage Notes

- Currently uses in-memory storage (dictionary-based)
- Passwords are hashed using SHA-256
- Certificate data is stored in DER format
- Entries follow LDAP-like structure with Distinguished Names (DNs)

## Future Enhancements

- Persistent storage (database or file-based)
- LDAP protocol support (LDAPv3)
- Replication support
- Access control lists (ACLs)

