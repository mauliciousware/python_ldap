"""
Certificate Manager

This module provides utilities for managing certificates:
- Generating Certificate Signing Requests (CSRs)
- Loading and saving certificates
- Certificate format conversion
"""

import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    """
    Utility class for managing certificates and CSRs.
    """
    
    @staticmethod
    def generate_csr(common_name, organization="Binghamton University", 
                    organizational_unit="CS Department", country="US",
                    state="New York", locality="Binghamton", email=None):
        """
        Generate a Certificate Signing Request (CSR).
        
        Args:
            common_name: Common name (CN) for the certificate
            organization: Organization name
            organizational_unit: Organizational unit name
            country: Country code
            state: State or province name
            locality: Locality name
            email: Email address (optional)
            
        Returns:
            Tuple of (CSR PEM string, private key object, private key PEM)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Build subject
        name_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
        
        if email:
            name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        
        subject = x509.Name(name_attributes)
        
        # Create CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Serialize
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        return csr_pem, private_key, private_key_pem
    
    @staticmethod
    def load_certificate(cert_path):
        """
        Load a certificate from file.
        
        Args:
            cert_path: Path to certificate file
            
        Returns:
            Certificate object
        """
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    
    @staticmethod
    def save_certificate(cert_pem, cert_path):
        """
        Save a certificate to file.
        
        Args:
            cert_pem: PEM-encoded certificate string
            cert_path: Path to save certificate
        """
        with open(cert_path, "w") as f:
            f.write(cert_pem)
    
    @staticmethod
    def save_private_key(private_key_pem, key_path):
        """
        Save a private key to file with secure permissions.
        
        Args:
            private_key_pem: PEM-encoded private key string
            key_path: Path to save private key
        """
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, "w") as f:
            f.write(private_key_pem)
        os.chmod(key_path, 0o600)
    
    @staticmethod
    def certificate_to_der(cert_pem):
        """
        Convert PEM certificate to DER format.
        
        Args:
            cert_pem: PEM-encoded certificate string
            
        Returns:
            DER-encoded certificate bytes
        """
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )
        return cert.public_bytes(serialization.Encoding.DER)
    
    @staticmethod
    def get_certificate_info(cert_pem):
        """
        Extract information from a certificate.
        
        Args:
            cert_pem: PEM-encoded certificate string
            
        Returns:
            Dictionary with certificate information
        """
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )
        
        info = {
            "subject": dict(cert.subject),
            "issuer": dict(cert.issuer),
            "serial_number": hex(cert.serial_number),
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
        }
        
        # Extract common name
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            info["common_name"] = cn[0].value
        
        return info

