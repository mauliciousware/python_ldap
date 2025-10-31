# Getting Started

## Installation

1. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

2. **Verify installation:**
```bash
python -c "import cryptography; print('Cryptography installed successfully')"
```

## Quick Start Example

```python
from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager
from ldap.directory import DirectoryService
from ldap.user_manager import UserManager

# Initialize CA
ca = CertificateAuthority()
ca.initialize()

# Initialize directory
directory = DirectoryService()
user_mgr = UserManager(directory)

# Create a user
user_mgr.create_user(
    username="john.doe",
    email="john@example.com",
    password="secret123"
)

# Generate a CSR
csr_pem, private_key, private_key_pem = CertificateManager.generate_csr(
    common_name="john.doe"
)

# Sign the certificate
cert_pem, cert_obj = ca.sign_csr(csr_pem, "john.doe", cert_type="client")

# Store certificate in directory
cert_der = CertificateManager.certificate_to_der(cert_pem)
directory.add_certificate_entry("john.doe", cert_der)
```

## Basic Operations

### 1. Setting Up the CA

```python
from ca.certificate_authority import CertificateAuthority

ca = CertificateAuthority()
ca.initialize()  # Generates root CA if it doesn't exist
```

### 2. Creating Users

```python
from ldap.directory import DirectoryService
from ldap.user_manager import UserManager

directory = DirectoryService()
user_mgr = UserManager(directory)

user_mgr.create_user(
    username="alice",
    email="alice@example.com",
    password="password123"
)
```

### 3. Issuing Certificates

```python
from ca.cert_manager import CertificateManager

# Generate CSR
csr_pem, private_key, private_key_pem = CertificateManager.generate_csr(
    common_name="server.example.com"
)

# Sign with CA
cert_pem, cert_obj = ca.sign_csr(csr_pem, "server.example.com", cert_type="server")
```

### 4. Secure Communication

```python
from client.secure_client import SecureClient
from server.secure_server import SecureServer

# Client side
client = SecureClient(ca.get_ca_certificate())
handshake_result = client.initiate_handshake(server_response)

# Server side
server = SecureServer("server.example.com", ca, ldap_server, server_key_pem)
response = server.handle_client_request({"type": "handshake"})
```

## Running the Demo

Run the complete workflow demo:

```bash
python tests/demo_full_workflow.py
```

This will demonstrate:
- CA initialization
- User creation
- Certificate issuance
- Secure communication
- Role-based access control

## Next Steps

- Read module-specific documentation in `docs/` directory
- Explore test scripts in `tests/` directory
- Review the architecture documentation

