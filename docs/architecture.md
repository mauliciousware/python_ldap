# System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                       │
├─────────────────────────────────────────────────────────────┤
│  Client Module  │  Server Module  │  Auth Module            │
└────────┬───────────────┬───────────────┬────────────────────┘
         │               │               │
┌────────▼───────────────▼───────────────▼────────────────────┐
│              LDAP Directory Service                           │
│  - User Management                                            │
│  - Certificate Storage                                         │
│  - Authentication                                             │
└────────┬──────────────────────────────────────────────────────┘
         │
┌────────▼──────────────────────────────────────────────────────┐
│              Certificate Authority (CA)                        │
│  - Root Certificate Generation                                │
│  - Certificate Signing                                        │
│  - Certificate Verification                                   │
└───────────────────────────────────────────────────────────────┘
```

## Module Interactions

### Certificate Authority Flow

```
1. CA.generate_root_ca()
   → Creates root certificate and private key
   → Stores in ca/ directory

2. CertificateManager.generate_csr()
   → Creates Certificate Signing Request
   → Returns CSR and private key

3. CA.sign_csr()
   → Verifies CSR signature
   → Signs certificate with CA private key
   → Returns signed certificate
```

### LDAP Directory Flow

```
1. DirectoryService.add_user()
   → Creates user entry
   → Stores in directory structure

2. DirectoryService.add_certificate_entry()
   → Creates certificate entry
   → Stores certificate in DER format

3. DirectoryService.search()
   → Searches directory with filters
   → Returns matching entries
```

### Secure Communication Flow

```
Client                          Server
  │                               │
  │─── Handshake Request ────────>│
  │                               │─── Generate Session Key
  │<── Certificate + Public Key ──│
  │                               │
  │─── Verify Certificate ────────│
  │                               │
  │─── Encrypted Session Key ────>│
  │                               │─── Decrypt Session Key
  │                               │
  │<─── Encrypted Messages ──────>│
  │                               │
```

### Role-Based Access Control Flow

```
1. User authenticates with directory
   ↓
2. User role is determined (OA/DA/User)
   ↓
3. Operation requested
   ↓
4. PermissionChecker checks permissions
   ↓
5. Operation allowed/denied based on role
```

## Data Flow

### Certificate Issuance

```
CSR Generation → CA Signing → Certificate Storage → LDAP Directory
```

### User Creation

```
User Data → Directory Service → Permission Check → Entry Creation
```

### Secure Communication

```
Certificate Exchange → Verification → Session Key Exchange → Encrypted Communication
```

## Security Architecture

### Encryption Layers

1. **Certificate Layer**: RSA-2048 for certificate signing
2. **Session Key Layer**: RSA-OAEP for session key encryption
3. **Message Layer**: AES-256-CBC for message encryption

### Authentication Flow

```
1. Client receives server certificate
2. Client verifies certificate against CA
3. Client encrypts session key with server's public key
4. Server decrypts session key with private key
5. Both sides use session key for encryption
```

## Directory Structure

```
dc=cs,dc=binghamton,dc=edu
├── ou=Certificates
│   ├── cn=server.example.com
│   └── cn=client.example.com
├── ou=Users
│   ├── cn=john.doe
│   └── cn=alice.smith
```

## File System Structure

```
python_ldap_ca/
├── ca/
│   ├── ca.crt              # Root CA certificate
│   ├── private/
│   │   └── ca.key          # Root CA private key
│   ├── certs/              # Signed certificates
│   └── serial              # Serial number tracker
├── ca/                     # CA module code
├── ldap/                   # LDAP module code
├── auth/                   # Auth module code
├── server/                 # Server module code
├── client/                 # Client module code
└── tests/                 # Test scripts
```

## Component Responsibilities

### Certificate Authority
- Generate root certificates
- Sign CSRs
- Verify certificates
- Manage certificate lifecycle

### Directory Service
- Store user/organization data
- Store certificates
- Handle authentication
- Provide search/modify operations

### Authentication Module
- Define roles and permissions
- Check permissions
- Enforce access control

### Server Module
- Handle client requests
- Enforce permissions
- Manage secure communication

### Client Module
- Initiate connections
- Verify certificates
- Send encrypted messages

## Extensibility

The system is designed to be extensible:

- **New Roles**: Add new role classes inheriting from `BaseRole`
- **New Permissions**: Add entries to `Permissions` enum
- **New Operations**: Add methods to `DirectoryService` and `LDAPServer`
- **New Encryption**: Extend `SecureChannel` with new algorithms

## Performance Considerations

- In-memory directory storage (can be extended to persistent storage)
- Efficient certificate verification using cryptography library
- Session keys cached for reuse during communication
- Permission checks cached when possible

