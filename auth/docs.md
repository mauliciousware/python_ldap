# Secure Communication Module Documentation

## Purpose

The secure communication module simulates TLS/SSL-like secure communication using certificate-based authentication and session key encryption. It provides end-to-end encryption for client-server communication.

## Key Components

### SecureChannel Class

Manages secure communication channels with certificate verification and encryption.

**Key Functions:**

- `verify_certificate()`: Verify certificate against CA
- `generate_session_key()`: Generate random session key
- `encrypt_session_key()`: Encrypt session key with public key
- `decrypt_session_key()`: Decrypt session key with private key
- `encrypt_message()`: Encrypt message with AES
- `decrypt_message()`: Decrypt message with AES

### SecureHandshake Class

Simulates TLS-like handshake process.

**Key Functions:**

- `server_handshake()`: Perform server-side handshake
- `client_handshake()`: Perform client-side handshake

## Communication Sequence

1. **CA issues certificate** → Certificate stored in directory
2. **Client requests ID** → Client initiates connection
3. **Server sends cert + public key** → Server responds with certificate
4. **Client verifies CA trust** → Client verifies certificate
5. **Client sends encrypted session key** → Session key encrypted with server's public key
6. **Both sides communicate** → Messages encrypted with session key

## Example Usage

```python
from auth.secure_communication import SecureChannel, SecureHandshake

# Server side
server_result = SecureHandshake.server_handshake(
    server_cert_pem,
    server_key_pem,
    ca_cert_pem
)

# Client side
client_result = SecureHandshake.client_handshake(
    ca_cert_pem,
    server_result
)

# Encrypt message
channel = client_result["channel"]
encrypted = channel.encrypt_message("Hello, server!")

# Decrypt message
decrypted = channel.decrypt_message(encrypted)
```

## Security Features

- **Certificate Verification**: Verifies certificates against CA before communication
- **RSA-OAEP Encryption**: Uses RSA-OAEP for session key encryption
- **AES-256-CBC**: Uses AES-256-CBC for message encryption
- **Random IVs**: Each message uses a random initialization vector

## Encryption Details

### Session Key Encryption
- Algorithm: RSA-OAEP
- Key Size: 2048 bits
- Hash: SHA-256

### Message Encryption
- Algorithm: AES-256-CBC
- Key Size: 256 bits (32 bytes)
- IV: Random 16 bytes per message
- Padding: PKCS7 padding

## How It Connects to the System

The secure communication module is used by:

1. **Server Module**: SecureServer uses SecureChannel for encrypted communication
2. **Client Module**: SecureClient uses SecureChannel for encrypted communication
3. **CA Module**: Certificate verification relies on CA certificate

## Security Notes

- Session keys are randomly generated for each connection
- Certificates are verified before establishing secure channels
- Private keys are never transmitted
- All communication after handshake is encrypted
