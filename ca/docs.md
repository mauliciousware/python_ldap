# Certificate Authority (CA) Module Documentation

## Purpose

The CA module provides complete certificate authority functionality for generating root certificates and signing certificate requests. This is the foundation of the PKI (Public Key Infrastructure) system.

## Key Components

### CertificateAuthority Class

The main class that handles all CA operations.

**Key Functions:**

- `initialize()`: Creates or loads the root CA certificate
- `generate_root_ca()`: Generates a self-signed root certificate
- `sign_csr()`: Signs a Certificate Signing Request (CSR) to create a certificate
- `verify_certificate()`: Verifies if a certificate is valid and signed by this CA
- `get_ca_certificate()`: Returns the CA certificate in PEM format

### CertificateManager Class

Utility class for managing certificates and CSRs.

**Key Functions:**

- `generate_csr()`: Creates a Certificate Signing Request
- `load_certificate()`: Loads a certificate from file
- `save_certificate()`: Saves a certificate to file
- `certificate_to_der()`: Converts PEM to DER format
- `get_certificate_info()`: Extracts information from a certificate

## Example Usage

```python
from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager

# Initialize CA
ca = CertificateAuthority()
ca.initialize()

# Generate a CSR
csr_pem, private_key, private_key_pem = CertificateManager.generate_csr(
    common_name="server.example.com"
)

# Sign the CSR
cert_pem, cert_obj = ca.sign_csr(csr_pem, "server.example.com", cert_type="server")

# Verify the certificate
is_valid = ca.verify_certificate(cert_pem)
print(f"Certificate is valid: {is_valid}")
```

## How It Connects to the System

The CA module is used by:

1. **Server Module**: Servers request certificates from the CA
2. **Client Module**: Clients verify server certificates using the CA certificate
3. **LDAP Module**: Certificates are stored in the LDAP directory
4. **Auth Module**: Certificates are used for authentication

## File Structure

- `ca/private/ca.key`: Root CA private key (kept secure)
- `ca/ca.crt`: Root CA certificate (public)
- `ca/certs/*.crt`: Signed certificates
- `ca/serial`: Serial number tracker for certificates

## Security Notes

- The CA private key is stored with 600 permissions (owner read/write only)
- Root CA certificate is valid for 10 years
- Signed certificates default to 1 year validity
- All certificates use SHA-256 for signing

