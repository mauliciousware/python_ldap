#!/usr/bin/env python3
"""
Complete workflow demonstration.

Demonstrates the full system workflow:
1. CA initialization
2. User creation
3. Certificate issuance
4. Secure communication setup
5. Role-based access control
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager
from ldap.directory import DirectoryService
from ldap.user_manager import UserManager
from server.ldap_server import LDAPServer
from auth.roles import OrganizationalAdmin, DomainAdmin
from auth.permissions import Permissions, PermissionChecker


def demo_ca_setup():
    """Demonstrate CA setup."""
    print("\n" + "=" * 70)
    print("Step 1: Certificate Authority Setup")
    print("=" * 70)
    
    ca = CertificateAuthority()
    ca.initialize()
    
    print("✓ Root CA certificate generated")
    print(f"✓ CA certificate location: {ca.ca_cert_path}")
    print(f"✓ CA private key location: {ca.ca_key_path}")
    
    return ca


def demo_user_management(ca):
    """Demonstrate user management."""
    print("\n" + "=" * 70)
    print("Step 2: User Management")
    print("=" * 70)
    
    directory = DirectoryService()
    user_mgr = UserManager(directory)
    
    # Create users
    user_mgr.create_user("alice", "alice@example.com", "password123", "Alice Smith")
    user_mgr.create_user("bob", "bob@example.com", "password456", "Bob Jones")
    
    print("✓ Created users: alice, bob")
    
    # List users
    users = user_mgr.list_users()
    print(f"✓ Total users in directory: {len(users)}")
    
    return directory, user_mgr


def demo_certificate_issuance(ca, directory):
    """Demonstrate certificate issuance."""
    print("\n" + "=" * 70)
    print("Step 3: Certificate Issuance")
    print("=" * 70)
    
    # Generate server CSR
    server_csr, server_key, server_key_pem = CertificateManager.generate_csr(
        common_name="ldap.example.com"
    )
    
    print("✓ Generated server CSR: ldap.example.com")
    
    # Sign server certificate
    server_cert_pem, server_cert = ca.sign_csr(
        server_csr,
        "ldap.example.com",
        cert_type="server"
    )
    
    print("✓ Server certificate signed by CA")
    
    # Store certificate in directory
    server_cert_der = CertificateManager.certificate_to_der(server_cert_pem)
    directory.add_certificate_entry("ldap.example.com", server_cert_der)
    
    print("✓ Server certificate stored in LDAP directory")
    
    # Generate client CSR
    client_csr, client_key, client_key_pem = CertificateManager.generate_csr(
        common_name="client.example.com"
    )
    
    print("✓ Generated client CSR: client.example.com")
    
    # Sign client certificate
    client_cert_pem, client_cert = ca.sign_csr(
        client_csr,
        "client.example.com",
        cert_type="client"
    )
    
    print("✓ Client certificate signed by CA")
    
    # Store certificate in directory
    client_cert_der = CertificateManager.certificate_to_der(client_cert_pem)
    directory.add_certificate_entry("client.example.com", client_cert_der)
    
    print("✓ Client certificate stored in LDAP directory")
    
    return server_cert_pem, server_key_pem, client_cert_pem, client_key_pem


def demo_role_based_access(directory):
    """Demonstrate role-based access control."""
    print("\n" + "=" * 70)
    print("Step 4: Role-Based Access Control")
    print("=" * 70)
    
    # Create roles
    oa = OrganizationalAdmin("admin")
    da = oa.create_domain_admin("da1", "example.com")
    
    print("✓ Created Organizational Admin: admin")
    print("✓ Created Domain Admin: da1 (domain: example.com)")
    
    # Check permissions
    checker = PermissionChecker()
    
    print("\nPermission Checks:")
    print(f"  OA can create users: {checker.check_permission(oa, Permissions.CREATE_USER)}")
    print(f"  OA can delete domain admins: {checker.check_permission(oa, Permissions.DELETE_DOMAIN_ADMIN)}")
    print(f"  DA can create users: {checker.check_permission(da, Permissions.CREATE_USER)}")
    print(f"  DA can delete domain admins: {checker.check_permission(da, Permissions.DELETE_DOMAIN_ADMIN)}")
    
    # Test server operations
    ldap_server = LDAPServer(directory)
    
    # OA can add users
    result = ldap_server.handle_request(
        "add_user",
        oa,
        username="charlie",
        attributes={"email": "charlie@example.com"},
        password="pass123"
    )
    print(f"\n✓ OA added user: {result['success']}")
    
    # DA can add users
    result = ldap_server.handle_request(
        "add_user",
        da,
        username="dave",
        attributes={"email": "dave@example.com"},
        password="pass456"
    )
    print(f"✓ DA added user: {result['success']}")
    
    return oa, da, ldap_server


def demo_secure_communication(ca, server_cert_pem, server_key_pem):
    """Demonstrate secure communication."""
    print("\n" + "=" * 70)
    print("Step 5: Secure Communication Simulation")
    print("=" * 70)
    
    from auth.secure_communication import SecureHandshake, SecureChannel
    
    ca_cert_pem = ca.get_ca_certificate()
    
    # Server handshake
    print("1. Server generates session key...")
    server_result = SecureHandshake.server_handshake(
        server_cert_pem,
        server_key_pem,
        ca_cert_pem
    )
    print("   ✓ Server handshake completed")
    
    # Client handshake
    print("2. Client verifies server certificate...")
    client_result = SecureHandshake.client_handshake(
        ca_cert_pem,
        server_result
    )
    print("   ✓ Client verified server certificate")
    print("   ✓ Session key encrypted with server's public key")
    
    # Encrypted communication
    print("3. Encrypted message exchange...")
    client_channel = client_result["channel"]
    
    message = "Hello, secure server!"
    encrypted = client_channel.encrypt_message(message)
    print(f"   ✓ Message encrypted: '{message}'")
    
    decrypted = client_channel.decrypt_message(encrypted)
    print(f"   ✓ Message decrypted: '{decrypted}'")
    
    assert message == decrypted, "Decrypted message should match original"
    print("   ✓ Encryption/decryption verified")
    
    print("\n✓ Secure communication established successfully")


def main():
    """Run complete workflow demonstration."""
    print("\n" + "=" * 70)
    print("Python-Based LDAP + CA System - Complete Workflow Demo")
    print("=" * 70)
    
    try:
        # Step 1: CA Setup
        ca = demo_ca_setup()
        
        # Step 2: User Management
        directory, user_mgr = demo_user_management(ca)
        
        # Step 3: Certificate Issuance
        server_cert_pem, server_key_pem, client_cert_pem, client_key_pem = demo_certificate_issuance(ca, directory)
        
        # Step 4: Role-Based Access Control
        oa, da, ldap_server = demo_role_based_access(directory)
        
        # Step 5: Secure Communication
        demo_secure_communication(ca, server_cert_pem, server_key_pem)
        
        print("\n" + "=" * 70)
        print("✓ All workflow steps completed successfully!")
        print("=" * 70)
        print("\nSummary:")
        print("  - CA initialized and operational")
        print("  - Users created and managed")
        print("  - Certificates issued and stored")
        print("  - Role-based access control enforced")
        print("  - Secure communication established")
        print()
        
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

