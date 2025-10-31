#!/usr/bin/env python3
"""
Test script for secure communication module.

Tests certificate verification, session key exchange, and message encryption.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager
from auth.secure_communication import SecureChannel, SecureHandshake


def test_certificate_verification():
    """Test certificate verification."""
    print("=" * 60)
    print("Test 1: Certificate Verification")
    print("=" * 60)
    
    ca = CertificateAuthority()
    ca.initialize()
    ca_cert_pem = ca.get_ca_certificate()
    
    # Generate and sign certificate
    csr_pem, _, _ = CertificateManager.generate_csr("test.example.com")
    cert_pem, _ = ca.sign_csr(csr_pem, "test.example.com")
    
    # Verify certificate
    channel = SecureChannel(ca_cert_pem)
    is_valid = channel.verify_certificate(cert_pem)
    
    assert is_valid, "Certificate should be valid"
    print("✓ Certificate verified successfully")
    print()


def test_session_key_exchange():
    """Test session key exchange."""
    print("=" * 60)
    print("Test 2: Session Key Exchange")
    print("=" * 60)
    
    ca = CertificateAuthority()
    ca.initialize()
    ca_cert_pem = ca.get_ca_certificate()
    
    # Generate server certificate
    server_csr, server_key, server_key_pem = CertificateManager.generate_csr("server.example.com")
    server_cert_pem, _ = ca.sign_csr(server_csr, "server.example.com", cert_type="server")
    
    # Server handshake
    server_result = SecureHandshake.server_handshake(
        server_cert_pem,
        server_key_pem,
        ca_cert_pem
    )
    
    assert "session_key" in server_result, "Should have session key"
    print("✓ Server generated session key")
    
    # Client handshake
    client_result = SecureHandshake.client_handshake(
        ca_cert_pem,
        server_result
    )
    
    assert "encrypted_session_key" in client_result, "Should have encrypted session key"
    print("✓ Client encrypted session key")
    
    # Server decrypts session key
    channel = SecureChannel(ca_cert_pem)
    decrypted_key = channel.decrypt_session_key(
        server_key_pem,
        client_result["encrypted_session_key"]
    )
    
    assert decrypted_key == server_result["session_key"], "Keys should match"
    print("✓ Server decrypted session key")
    print()


def test_message_encryption():
    """Test message encryption/decryption."""
    print("=" * 60)
    print("Test 3: Message Encryption")
    print("=" * 60)
    
    ca = CertificateAuthority()
    ca.initialize()
    ca_cert_pem = ca.get_ca_certificate()
    
    channel = SecureChannel(ca_cert_pem)
    session_key = channel.generate_session_key()
    
    # Encrypt message
    message = "This is a secret message!"
    encrypted = channel.encrypt_message(message, session_key)
    
    assert len(encrypted) > len(message), "Encrypted should be longer"
    print(f"✓ Message encrypted: '{message}'")
    
    # Decrypt message
    decrypted = channel.decrypt_message(encrypted, session_key)
    
    assert decrypted == message, "Decrypted should match original"
    print(f"✓ Message decrypted: '{decrypted}'")
    print()


def test_end_to_end_communication():
    """Test end-to-end secure communication."""
    print("=" * 60)
    print("Test 4: End-to-End Communication")
    print("=" * 60)
    
    ca = CertificateAuthority()
    ca.initialize()
    ca_cert_pem = ca.get_ca_certificate()
    
    # Setup server
    server_csr, server_key, server_key_pem = CertificateManager.generate_csr("server.example.com")
    server_cert_pem, _ = ca.sign_csr(server_csr, "server.example.com", cert_type="server")
    
    # Handshake
    server_result = SecureHandshake.server_handshake(
        server_cert_pem,
        server_key_pem,
        ca_cert_pem
    )
    
    client_result = SecureHandshake.client_handshake(
        ca_cert_pem,
        server_result
    )
    
    # Client sends message
    client_channel = client_result["channel"]
    message = "Hello from client!"
    encrypted_msg = client_channel.encrypt_message(message)
    
    print(f"✓ Client encrypted message: '{message}'")
    
    # Server receives and decrypts
    server_channel = server_result["channel"]
    decrypted_msg = server_channel.decrypt_message(encrypted_msg, server_result["session_key"])
    
    print(f"✓ Server decrypted message: '{decrypted_msg}'")
    
    assert decrypted_msg == message, "Messages should match"
    print("✓ End-to-end communication verified")
    print()


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("Secure Communication Module Tests")
    print("=" * 60 + "\n")
    
    try:
        test_certificate_verification()
        test_session_key_exchange()
        test_message_encryption()
        test_end_to_end_communication()
        
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

