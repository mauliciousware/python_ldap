# System Overview

## Introduction

This Python-based LDAP + Certificate Authority (CA) system provides a complete implementation of a Public Key Infrastructure (PKI) integrated with a directory service. It recreates the functionality that was previously implemented manually.

## Architecture

The system consists of five main modules:

### 1. Certificate Authority (CA) Module
- Generates root CA certificates
- Signs Certificate Signing Requests (CSRs)
- Manages certificate lifecycle
- Verifies certificates

### 2. LDAP-like Directory Service Module
- Stores user and organizational data
- Provides add, search, modify, delete operations
- Manages certificate entries
- Handles authentication

### 3. Authentication and Authorization Module
- Defines roles (OA, DA, User)
- Manages permissions
- Enforces access control

### 4. Server Module
- Handles LDAP operations
- Manages secure communication
- Enforces permissions

### 5. Client Module
- Provides client-side LDAP operations
- Handles secure communication
- Verifies certificates

## Communication Flow

```
1. CA issues certificate
   ↓
2. Certificate stored in LDAP directory
   ↓
3. Client requests server ID
   ↓
4. Server sends certificate + public key
   ↓
5. Client verifies CA trust
   ↓
6. Client sends encrypted session key
   ↓
7. Both sides communicate using session key
```

## Key Features

- **Certificate Management**: Complete PKI with root CA and certificate signing
- **Directory Service**: LDAP-like storage for users and certificates
- **Secure Communication**: TLS-like encrypted communication
- **Role-Based Access**: OA and DA roles with granular permissions
- **Modular Design**: Clean separation of concerns

## Security Features

- RSA-2048 key pairs for certificates
- SHA-256 for certificate signing
- AES-256-CBC for message encryption
- RSA-OAEP for session key encryption
- Certificate verification against CA
- Permission-based access control

## Use Cases

1. **Certificate Issuance**: Generate and sign certificates for servers/clients
2. **User Management**: Add, modify, and manage users in the directory
3. **Secure Communication**: Establish encrypted channels between clients and servers
4. **Access Control**: Enforce permissions based on user roles

## Getting Started

See `docs/getting_started.md` for detailed setup instructions.

## Module Documentation

- `ca/docs.md` - Certificate Authority documentation
- `ldap/docs.md` - Directory service documentation
- `auth/docs.md` - Authentication and authorization documentation
- `server/docs.md` - Server module documentation
- `client/docs.md` - Client module documentation

