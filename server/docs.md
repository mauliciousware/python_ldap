# Server Module Documentation

## Purpose

The server module provides server-side functionality for handling LDAP operations and secure communication. It enforces permissions and manages encrypted communication channels.

## Key Components

### LDAPServer Class

Handles directory operations with permission checking.

**Key Functions:**

- `handle_request()`: Process directory operation requests
- `add_user()`: Add a user to the directory
- `search()`: Search the directory
- `modify()`: Modify directory entries
- `delete()`: Delete directory entries
- `authenticate()`: Authenticate users

### SecureServer Class

Handles secure, certificate-based communication with clients.

**Key Functions:**

- `handle_client_request()`: Process client requests
- `_handle_handshake()`: Perform TLS-like handshake
- `_handle_encrypted_message()`: Process encrypted messages
- `send_certificate()`: Send certificate and public key to client

## Example Usage

```python
from server.ldap_server import LDAPServer
from server.secure_server import SecureServer
from ldap.directory import DirectoryService
from ca.certificate_authority import CertificateAuthority
from auth.roles import OrganizationalAdmin

# Initialize components
directory = DirectoryService()
ldap_server = LDAPServer(directory)
ca = CertificateAuthority()
ca.initialize()

# Create OA role
oa = OrganizationalAdmin("admin")

# Add a user
result = ldap_server.handle_request(
    "add_user",
    oa,
    username="john.doe",
    attributes={"email": "john@example.com"},
    password="secret123"
)

# Create secure server
secure_server = SecureServer(
    server_name="ldap.example.com",
    ca=ca,
    ldap_server=ldap_server,
    server_key_pem=server_key_pem
)

# Handle client request
response = secure_server.handle_client_request({
    "type": "handshake"
})
```

## Communication Flow

1. **Client initiates handshake**: Client requests server certificate
2. **Server responds**: Server sends certificate and public key
3. **Client verifies**: Client verifies certificate against CA
4. **Session key exchange**: Client encrypts session key with server's public key
5. **Encrypted communication**: Both sides use session key for encryption

## How It Connects to the System

The server module is used by:

1. **Client Module**: Clients connect to the server for operations
2. **CA Module**: Server uses CA to verify certificates
3. **LDAP Module**: Server uses directory service for data storage
4. **Auth Module**: Server checks permissions before processing requests

## Security Features

- Certificate-based authentication
- Session key encryption using RSA-OAEP
- Message encryption using AES-256-CBC
- Permission checking on all operations
- Certificate verification against CA

## Error Handling

All operations return dictionaries with `success` field and optional `error` field for error cases.

