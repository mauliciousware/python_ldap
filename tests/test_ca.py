#!/usr/bin/env python3
"""
Test script for Certificate Authority module.

Tests CA initialization, CSR generation, and certificate signing.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager


def test_ca_initialization():
    """Test CA initialization."""
    print("=" * 60)
    print("Test 1: CA Initialization")
    print("=" * 60)
    
    ca = CertificateAuthority()
    ca.initialize()
    
    print("✓ CA initialized successfully")
    print(f"✓ CA certificate stored at: {ca.ca_cert_path}")
    print(f"✓ CA private key stored at: {ca.ca_key_path}")
    
    # Verify CA certificate can be loaded
    ca_cert_pem = ca.get_ca_certificate()
    assert len(ca_cert_pem) > 0, "CA certificate should not be empty"
    print("✓ CA certificate loaded successfully")
    print()


def test_csr_generation():
    """Test CSR generation."""
    print("=" * 60)
    print("Test 2: CSR Generation")
    print("=" * 60)
    
    csr_pem, private_key, private_key_pem = CertificateManager.generate_csr(
        common_name="test.example.com",
        email="test@example.com"
    )
    
    assert len(csr_pem) > 0, "CSR should not be empty"
    assert private_key is not None, "Private key should be generated"
    assert len(private_key_pem) > 0, "Private key PEM should not be empty"
    
    print("✓ CSR generated successfully")
    print(f"✓ Common Name: test.example.com")
    print(f"✓ CSR length: {len(csr_pem)} bytes")
    print()


def test_certificate_signing():
    """Test certificate signing."""
    print("=" * 60)
    print("Test 3: Certificate Signing")
    print("=" * 60)
    
    # Initialize CA
    ca = CertificateAuthority()
    ca.initialize()
    
    # Generate CSR
    csr_pem, private_key, private_key_pem = CertificateManager.generate_csr(
        common_name="server.example.com"
    )
    
    # Sign certificate
    cert_pem, cert_obj = ca.sign_csr(
        csr_pem,
        "server.example.com",
        cert_type="server"
    )
    
    assert len(cert_pem) > 0, "Certificate should not be empty"
    assert cert_obj is not None, "Certificate object should be created"
    
    print("✓ Certificate signed successfully")
    print(f"✓ Certificate serial number: {cert_obj.serial_number}")
    print(f"✓ Certificate valid from: {cert_obj.not_valid_before}")
    print(f"✓ Certificate valid until: {cert_obj.not_valid_after}")
    
    # Verify certificate
    is_valid = ca.verify_certificate(cert_pem)
    assert is_valid, "Certificate should be valid"
    print("✓ Certificate verified successfully")
    print()


def test_certificate_info():
    """Test certificate information extraction."""
    print("=" * 60)
    print("Test 4: Certificate Information")
    print("=" * 60)
    
    ca = CertificateAuthority()
    ca.initialize()
    
    csr_pem, _, _ = CertificateManager.generate_csr(
        common_name="client.example.com"
    )
    
    cert_pem, _ = ca.sign_csr(csr_pem, "client.example.com", cert_type="client")
    
    info = CertificateManager.get_certificate_info(cert_pem)
    
    print("✓ Certificate information extracted:")
    print(f"  Common Name: {info.get('common_name', 'N/A')}")
    print(f"  Serial Number: {info.get('serial_number', 'N/A')}")
    print(f"  Valid From: {info.get('not_valid_before', 'N/A')}")
    print(f"  Valid Until: {info.get('not_valid_after', 'N/A')}")
    print()


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("Certificate Authority Module Tests")
    print("=" * 60 + "\n")
    
    try:
        test_ca_initialization()
        test_csr_generation()
        test_certificate_signing()
        test_certificate_info()
        
        print("=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

