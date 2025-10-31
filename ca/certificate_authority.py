"""
Certificate Authority Implementation

This module implements the core Certificate Authority functionality:
- Generates root CA key and certificate
- Signs Certificate Signing Requests (CSRs)
- Manages certificate serial numbers
- Stores certificates in organized directory structure
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateAuthority:
    """
    Certificate Authority class that handles root certificate generation
    and certificate signing operations.
    """
    
    def __init__(self, ca_dir="ca"):
        """
        Initialize the Certificate Authority.
        
        Args:
            ca_dir: Directory path for storing CA files
        """
        self.ca_dir = ca_dir
        self.private_dir = os.path.join(ca_dir, "private")
        self.certs_dir = os.path.join(ca_dir, "certs")
        self.ca_key_path = os.path.join(self.private_dir, "ca.key")
        self.ca_cert_path = os.path.join(ca_dir, "ca.crt")
        self.serial_file = os.path.join(ca_dir, "serial")
        
        # Create directories if they don't exist
        os.makedirs(self.private_dir, mode=0o700, exist_ok=True)
        os.makedirs(self.certs_dir, mode=0o755, exist_ok=True)
        
        self._private_key = None
        self._ca_certificate = None
    
    def initialize(self):
        """
        Initialize the CA by generating root certificate if it doesn't exist.
        """
        if not os.path.exists(self.ca_key_path) or not os.path.exists(self.ca_cert_path):
            print("Generating root CA certificate...")
            self.generate_root_ca()
        else:
            print("Loading existing CA...")
            self._load_ca()
    
    def generate_root_ca(self):
        """
        Generate a self-signed root CA certificate and private key.
        """
        # Generate private key
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate subject and issuer (same for root CA)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Binghamton"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Binghamton University CS Department"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "BU CS PKI Root CA"),
        ])
        
        # Create certificate
        self._ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self._private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).sign(self._private_key, hashes.SHA256(), default_backend())
        
        # Save private key
        with open(self.ca_key_path, "wb") as f:
            f.write(self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(self.ca_key_path, 0o600)
        
        # Save certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(self._ca_certificate.public_bytes(serialization.Encoding.PEM))
        
        print(f"Root CA certificate generated and saved to {self.ca_cert_path}")
    
    def _load_ca(self):
        """Load existing CA key and certificate from disk."""
        with open(self.ca_key_path, "rb") as f:
            self._private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        with open(self.ca_cert_path, "rb") as f:
            self._ca_certificate = x509.load_pem_x509_certificate(
                f.read(), default_backend()
            )
    
    def sign_csr(self, csr_pem, common_name, cert_type="server", validity_days=365):
        """
        Sign a Certificate Signing Request (CSR).
        
        Args:
            csr_pem: PEM-encoded CSR string
            common_name: Common name for the certificate
            cert_type: Type of certificate ("server" or "client")
            validity_days: Certificate validity period in days
            
        Returns:
            Tuple of (certificate PEM, certificate object)
        """
        if not self._private_key or not self._ca_certificate:
            raise RuntimeError("CA not initialized. Call initialize() first.")
        
        # Load CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        
        # Verify CSR signature
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            raise ValueError(f"Invalid CSR signature: {e}")
        
        # Build certificate
        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self._ca_certificate.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            self._get_next_serial()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        )
        
        # Add extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        
        key_usage_flags = {
            "server": [True, True, False, False, False, False, False, False, False],
            "client": [True, False, False, False, False, False, False, False, False]
        }
        
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=key_usage_flags.get(cert_type, [True])[0],
                key_encipherment=key_usage_flags.get(cert_type, [False])[1],
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False
            ), critical=True
        )
        
        # Add extended key usage
        if cert_type == "server":
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False
            )
        elif cert_type == "client":
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False
            )
        
        # Sign certificate
        certificate = builder.sign(
            self._private_key, hashes.SHA256(), default_backend()
        )
        
        # Save certificate
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        cert_filename = os.path.join(self.certs_dir, f"{common_name}.crt")
        with open(cert_filename, "w") as f:
            f.write(cert_pem)
        
        print(f"Certificate signed and saved to {cert_filename}")
        return cert_pem, certificate
    
    def _get_next_serial(self):
        """Get next serial number for certificate."""
        if os.path.exists(self.serial_file):
            with open(self.serial_file, "r") as f:
                serial = int(f.read().strip(), 16) + 1
        else:
            serial = 1
        
        with open(self.serial_file, "w") as f:
            f.write(hex(serial)[2:].upper())
        
        return serial
    
    def get_ca_certificate(self):
        """Get the CA certificate in PEM format."""
        if not self._ca_certificate:
            raise RuntimeError("CA not initialized")
        return self._ca_certificate.public_bytes(serialization.Encoding.PEM).decode()
    
    def verify_certificate(self, cert_pem):
        """
        Verify a certificate against the CA.
        
        Args:
            cert_pem: PEM-encoded certificate string
            
        Returns:
            True if certificate is valid and signed by this CA
        """
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            
            # Verify signature
            self._ca_certificate.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                hashes.SHA256(),
                default_backend()
            )
            
            # Check validity period
            now = datetime.utcnow()
            if cert.not_valid_before > now or cert.not_valid_after < now:
                return False
            
            return True
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            return False

