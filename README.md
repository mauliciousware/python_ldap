# Python-Based LDAP + Certificate Authority (CA) System

A comprehensive Python implementation of a Certificate Authority integrated with an LDAP-like directory service, featuring secure communication simulation and role-based access control.

## Project Overview

This project recreates the functionality of a manual LDAP + CA setup using pure Python. It provides:

- **Certificate Authority (CA)**: Generate root certificates and sign server/client certificates
- **LDAP-like Directory Service**: Store and manage user/organization data
- **Secure Communication**: Simulated TLS/SSL-like exchange with certificate verification
- **Role-Based Access Control**: Organizational Admin (OA) and Domain Admin (DA) roles

## Project Structure

```
python_ldap_ca/
├── ca/                    # Certificate Authority module
├── ldap/                  # LDAP-like directory service
├── auth/                  # Authentication and authorization
├── server/                # Server-side simulation
├── client/                # Client-side simulation
├── docs/                  # Documentation
└── tests/                 # Test scripts
```

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the demo:
```bash
python tests/demo_full_workflow.py
```

## Quick Start

```python
from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager
from ldap.directory import DirectoryService
from ldap.user_manager import UserManager

# Initialize CA
ca = CertificateAuthority()
ca.initialize()

# Initialize LDAP directory
directory = DirectoryService()
user_mgr = UserManager(directory)

# Add a user
user_mgr.create_user("john.doe", "john@example.com", "secret123")

# Generate a CSR
csr_pem, private_key, private_key_pem = CertificateManager.generate_csr(
    common_name="john.doe"
)

# Issue a certificate
cert_pem, cert_obj = ca.sign_csr(csr_pem, "john.doe", cert_type="client")
```

## Features

- **CA Operations**: Root certificate generation, CSR signing, certificate storage
- **Directory Operations**: Add, search, modify, delete users and organizations
- **Secure Communication**: Certificate-based authentication and session key exchange
- **Role Management**: OA and DA roles with granular permissions

## Running Tests

```bash
# Test CA module
python tests/test_ca.py

# Test LDAP module
python tests/test_ldap.py

# Test secure communication
python tests/test_secure_communication.py

# Run complete workflow demo
python tests/demo_full_workflow.py
```

## Documentation

See the `docs/` directory for detailed documentation:
- `docs/overview.md` - System overview
- `docs/getting_started.md` - Quick start guide
- `docs/architecture.md` - Architecture details

Each module also has its own documentation:
- `ca/docs.md` - Certificate Authority
- `ldap/docs.md` - Directory Service
- `auth/docs.md` - Authentication & Authorization
- `server/docs.md` - Server Module
- `client/docs.md` - Client Module

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

## Security Features

- RSA-2048 key pairs for certificates
- SHA-256 for certificate signing
- AES-256-CBC for message encryption
- RSA-OAEP for session key encryption
- Certificate verification against CA
- Permission-based access control

## Requirements

- Python 3.7+
- cryptography library (see requirements.txt)

## License

Educational use - Binghamton University CS Department

# python_ldap
