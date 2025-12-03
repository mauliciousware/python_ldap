#!/usr/bin/env python3
"""
Full Workflow Demo

This script demonstrates the complete lifecycle of the LDAP CA system:
1. Initialize Certificate Authority
2. Setup Directory Service and LDAP Server
3. Create users with automatic certificate issuance
4. Perform mutual TLS handshake
5. Exchange encrypted messages

Run this to verify the system is working correctly.
"""

import sys
import os
import shutil

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager
from ldap.directory import DirectoryService
from ldap.user_manager import UserManager
from server.ldap_server import LDAPServer
from server.secure_server import SecureServer
from client.secure_client import SecureClient
from auth.roles import OrganizationalAdmin, DomainAdmin, RegularUser
from auth.permissions import Permissions


def print_step(step_num: int, title: str):
    """Print a formatted step header."""
    print(f"\n{'='*60}")
    print(f"  Step {step_num}: {title}")
    print('='*60)


def print_check(message: str, success: bool = True):
    """Print a checkmark or X with message."""
    symbol = "✓" if success else "✗"
    print(f"  {symbol} {message}")


def demo_full_workflow():
    """Run the complete system workflow demonstration."""
    
    print("\n" + "="*60)
    print("  PYTHON LDAP & CA SYSTEM - FULL WORKFLOW DEMO")
    print("="*60)
    
    demo_dir = "demo_full_workflow_data"
    
    # Cleanup previous run
    if os.path.exists(demo_dir):
        shutil.rmtree(demo_dir)
    os.makedirs(demo_dir, exist_ok=True)
    
    all_passed = True
    
    try:
        # ============================================================
        # Step 1: Initialize Certificate Authority
        # ============================================================
        print_step(1, "Initialize Certificate Authority")
        
        ca = CertificateAuthority(ca_dir=demo_dir)
        ca.initialize()
        
        ca_cert = ca.get_ca_certificate()
        print_check(f"Root CA created at: {demo_dir}/ca.crt")
        print_check(f"CA private key stored at: {demo_dir}/private/ca.key")
        
        # ============================================================
        # Step 2: Setup Directory Service
        # ============================================================
        print_step(2, "Setup Directory Service")
        
        directory = DirectoryService()
        ldap_server = LDAPServer(directory, ca=ca)
        
        print_check("Directory Service initialized")
        print_check("LDAP Server started with CA integration")
        print_check(f"Base DN: {directory.base_dn}")
        
        # ============================================================
        # Step 3: Create Users with Certificate Issuance
        # ============================================================
        print_step(3, "Create Users with Certificate Issuance")
        
        user_manager = UserManager(directory, ca=ca)
        
        # Create multiple users
        users_data = [
            ("alice", "alice@example.com", "Alice Anderson"),
            ("bob", "bob@example.com", "Bob Brown"),
            ("charlie", "charlie@example.com", "Charlie Chen"),
        ]
        
        user_certs = {}
        for username, email, full_name in users_data:
            dn, cert_info = user_manager.create_user(
                username=username,
                email=email,
                password=f"{username}_password",
                full_name=full_name,
                issue_certificate=True
            )
            user_certs[username] = cert_info
            print_check(f"User '{username}' created with certificate")
        
        # ============================================================
        # Step 4: Verify Certificate Chain
        # ============================================================
        print_step(4, "Verify Certificate Chain")
        
        for username in user_certs:
            is_valid = ca.verify_certificate(user_certs[username]["cert_pem"])
            if is_valid:
                print_check(f"{username}'s certificate verified against CA")
            else:
                print_check(f"{username}'s certificate FAILED verification", False)
                all_passed = False
        
        # ============================================================
        # Step 5: Test Role-Based Access Control
        # ============================================================
        print_step(5, "Test Role-Based Access Control")
        
        oa = OrganizationalAdmin("admin")
        da = DomainAdmin("domain_admin", "cs.binghamton.edu")
        user = RegularUser("regular_user")
        
        # Check OA permissions
        oa_has_manage = oa.has_permission(Permissions.MANAGE_ORGANIZATION)
        print_check(f"OA can manage organization: {oa_has_manage}")
        
        # Check DA permissions
        da_has_manage = da.has_permission(Permissions.MANAGE_ORGANIZATION)
        da_has_create = da.has_permission(Permissions.CREATE_USER)
        print_check(f"DA can manage organization: {da_has_manage}")
        print_check(f"DA can create users: {da_has_create}")
        
        # Check Regular User permissions
        user_has_view = user.has_permission(Permissions.VIEW_USER)
        user_has_create = user.has_permission(Permissions.CREATE_USER)
        print_check(f"User can view users: {user_has_view}")
        print_check(f"User can create users: {user_has_create}")
        
        # ============================================================
        # Step 6: Setup Secure Server (Bob as server)
        # ============================================================
        print_step(6, "Setup Secure Server")
        
        # Create server certificate for Bob
        csr_pem, _, server_key_pem = CertificateManager.generate_csr("bob_server")
        server_cert_pem, _ = ca.sign_csr(csr_pem, "bob_server", cert_type="server")
        cert_der = CertificateManager.certificate_to_der(server_cert_pem)
        directory.add_certificate_entry("bob_server", cert_der)
        
        secure_server = SecureServer(
            server_name="bob_server",
            ca=ca,
            ldap_server=ldap_server,
            server_key_pem=server_key_pem
        )
        print_check("Secure Server (Bob) initialized")
        
        # ============================================================
        # Step 7: Mutual TLS Handshake
        # ============================================================
        print_step(7, "Perform Mutual TLS Handshake")
        
        secure_client = SecureClient(
            ca_cert_pem=ca.get_ca_certificate(),
            client_cert_pem=user_certs["alice"]["cert_pem"],
            client_key_pem=user_certs["alice"]["private_key_pem"]
        )
        
        # Initiate handshake
        client_hello = secure_client.initiate_mutual_handshake()
        print_check("Alice sent ClientHello with certificate")
        
        # Server processes handshake
        server_response = secure_server.handle_client_request(client_hello)
        if server_response.get("success"):
            print_check("Bob verified Alice's certificate")
            print_check("Bob created encrypted session key")
        else:
            print_check(f"Handshake failed: {server_response.get('error')}", False)
            all_passed = False
        
        # Client completes handshake
        handshake_result = secure_client.complete_mutual_handshake(server_response)
        if handshake_result.get("success"):
            print_check("Alice verified Bob's certificate")
            print_check("Alice decrypted session key")
            print_check("Mutual TLS handshake COMPLETE")
        else:
            print_check(f"Handshake failed: {handshake_result.get('error')}", False)
            all_passed = False
        
        # ============================================================
        # Step 8: Encrypted Message Exchange
        # ============================================================
        print_step(8, "Exchange Encrypted Messages")
        
        test_message = "Hello Bob! This is a secure message from Alice."
        
        # Send encrypted message
        encrypted_request = secure_client.send_encrypted_message(test_message)
        print_check(f"Alice encrypted: \"{test_message[:30]}...\"")
        print_check(f"Ciphertext length: {len(encrypted_request['encrypted_message'])} hex chars")
        
        # Server processes message
        server_response = secure_server.handle_client_request(encrypted_request)
        if server_response.get("success"):
            print_check("Bob decrypted and processed message")
        else:
            print_check(f"Message processing failed: {server_response.get('error')}", False)
            all_passed = False
        
        # Client decrypts response
        decrypted_response = secure_client.receive_encrypted_message(server_response)
        print_check(f"Alice received: \"{decrypted_response[:40]}...\"")
        
        if test_message in decrypted_response:
            print_check("Message roundtrip VERIFIED")
        else:
            print_check("Message verification failed", False)
            all_passed = False
        
        # ============================================================
        # Final Summary
        # ============================================================
        print("\n" + "="*60)
        if all_passed:
            print("  ✓ ALL WORKFLOW STEPS COMPLETED SUCCESSFULLY!")
        else:
            print("  ✗ SOME STEPS FAILED - CHECK OUTPUT ABOVE")
        print("="*60)
        
        return all_passed
        
    except Exception as e:
        print(f"\n  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        if os.path.exists(demo_dir):
            shutil.rmtree(demo_dir)
        print(f"\n  Cleaned up temporary directory: {demo_dir}")


if __name__ == "__main__":
    success = demo_full_workflow()
    sys.exit(0 if success else 1)
