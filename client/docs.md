# Client Module Documentation

## Purpose

The client module provides client-side functionality for communicating with the LDAP server securely. It handles certificate verification and encrypted communication.

## Key Components

### LDAPClient Class

Client for LDAP operations.

**Key Functions:**

- `add_user()`: Add a user
- `search()`: Search the directory
- `modify()`: Modify entries
- `delete()`: Delete entries
- `authenticate()`: Authenticate user

### SecureClient Class

Secure client for encrypted communication.

**Key Functions:**

- `initiate_handshake()`: Start TLS-like handshake with server
- `send_encrypted_message()`: Send encrypted message
- `receive_encrypted_message()`: Decrypt server response
- `verify_server_certificate()`: Verify server certificate
- `request_server_certificate()`: Request server certificate

## Example Usage

```python
from client.secure_client import SecureClient
from client.ldap_client import LDAPClient
from server.ldap_server import LDAPServer
from auth.roles import RegularUser

# Initialize secure client
secure_client = SecureClient(ca_cert_pem)

# Request server certificate
server_response = {
    "server_certificate": server_cert_pem,
    "server_public_key": server_pub_key_pem,
    "session_key": session_key_bytes
}

# Initiate handshake
handshake_result = secure_client.initiate_handshake(server_response)

# Send encrypted message
encrypted_request = secure_client.send_encrypted_message(
    "Hello, server!",
    bytes.fromhex(handshake_result["encrypted_session_key"])
)

# Receive encrypted response
encrypted_response = {"encrypted_message": "..."}
decrypted = secure_client.receive_encrypted_message(encrypted_response)
```

## Secure Communication Flow

1. **Client requests certificate**: Client sends handshake request
2. **Server sends certificate**: Server responds with certificate and public key
3. **Client verifies**: Client verifies certificate against CA
4. **Session key encryption**: Client encrypts session key with server's public key
5. **Encrypted messages**: All subsequent messages are encrypted

## How It Connects to the System

The client module is used by:

1. **Server Module**: Clients connect to servers
2. **CA Module**: Clients use CA certificate to verify server certificates
3. **Auth Module**: Client operations are subject to permission checks

## Security Features

- Certificate verification before communication
- Session key encryption using RSA-OAEP
- Message encryption using AES-256-CBC
- Protection against man-in-the-middle attacks

## Error Handling

All operations return dictionaries with `success` field. Errors are returned in the `error` field.

