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


def format_bytes_display(data: bytes, label: str, max_display: int = 64) -> None:
    """Display bytes in a readable format."""
    hex_str = data.hex()
    if len(hex_str) > max_display:
        display = f"{hex_str[:max_display]}..."
    else:
        display = hex_str
    print(f"   {label}")
    print(f"   Hex ({len(data)} bytes): {display}")


def demo_alice_bob_comm():
    print("=" * 70)
    print("   SECURE COMMUNICATION DEMO: ALICE ↔ BOB")
    print("   With Mutual TLS Authentication (Prevents MITM Attacks)")
    print("=" * 70)

    demo_ca_dir = "demo_ca_alice_bob"
    if os.path.exists(demo_ca_dir):
        shutil.rmtree(demo_ca_dir)

    os.makedirs(demo_ca_dir, exist_ok=True)

    try:
        # ============================================================
        # STEP 1: Initialize Certificate Authority (CA)
        # ============================================================
        print("\n" + "─" * 70)
        print("STEP 1: Initializing Certificate Authority (CA)")
        print("─" * 70)
        ca = CertificateAuthority(ca_dir=demo_ca_dir)
        ca.initialize()
        print(f"   ✓ CA initialized at: {demo_ca_dir}")

        # ============================================================
        # STEP 2: Initialize Directory Service and LDAP Server
        # ============================================================
        print("\n" + "─" * 70)
        print("STEP 2: Starting Directory Service and LDAP Server")
        print("─" * 70)
        directory = DirectoryService()
        ldap_server = LDAPServer(directory, ca=ca)
        print("   ✓ Directory Service started")
        print("   ✓ LDAP Server started with CA integration")

        # ============================================================
        # STEP 3: Create Users with Certificate Issuance via CA
        # ============================================================
        print("\n" + "─" * 70)
        print("STEP 3: Creating Users with Certificate Issuance via CA")
        print("─" * 70)
        
        # Initialize UserManager with CA (certificates issued during user creation)
        user_manager = UserManager(directory, ca=ca)
        
        # Create Alice (will act as client)
        print("\n   Creating Alice...")
        alice_dn, alice_cert_info = user_manager.create_user(
            username="alice",
            email="alice@example.com",
            password="alice_password",
            full_name="Alice Smith",
            issue_certificate=True  # Certificate issued via CA during creation
        )
        print(f"   ✓ Alice created: {alice_dn}")
        
        # Create Bob (will act as server)
        print("\n   Creating Bob...")
        bob_dn, bob_cert_info = user_manager.create_user(
            username="bob",
            email="bob@example.com",
            password="bob_password",
            full_name="Bob Jones",
            issue_certificate=True  # Certificate issued via CA during creation
        )
        print(f"   ✓ Bob created: {bob_dn}")

        # For Bob as server, we need a server-type certificate
        print("\n   Issuing server certificate for Bob...")
        csr_pem_bob, _, bob_server_key_pem = CertificateManager.generate_csr("bob_server")
        bob_server_cert_pem, _ = ca.sign_csr(csr_pem_bob, "bob_server", cert_type="server")
        cert_der_bob = CertificateManager.certificate_to_der(bob_server_cert_pem)
        directory.add_certificate_entry("bob_server", cert_der_bob)
        print("   ✓ Server certificate issued for Bob")

        # ============================================================
        # STEP 4: Start Secure Server (Bob)
        # ============================================================
        print("\n" + "─" * 70)
        print("STEP 4: Starting Secure Server (Bob)")
        print("─" * 70)
        secure_server = SecureServer(
            server_name="bob_server",
            ca=ca,
            ldap_server=ldap_server,
            server_key_pem=bob_server_key_pem,
        )
        print("   ✓ Bob's Secure Server started")

        # ============================================================
        # STEP 5: Mutual TLS Handshake (Alice → Bob)
        # ============================================================
        print("\n" + "─" * 70)
        print("STEP 5: Mutual TLS Handshake (MITM Prevention)")
        print("─" * 70)
        
        # Alice creates secure client with her certificate
        secure_client = SecureClient(
            ca_cert_pem=ca.get_ca_certificate(),
            client_cert_pem=alice_cert_info["cert_pem"],
            client_key_pem=alice_cert_info["private_key_pem"]
        )
        
        print("\n   [Alice → Bob] Sending ClientHello with certificate...")
        client_hello = secure_client.initiate_mutual_handshake()
        print(f"   Request type: {client_hello['type']}")
        print(f"   Client certificate attached: Yes ({len(client_hello['client_certificate'])} chars)")
        
        # Bob receives and verifies Alice's certificate, then creates session key
        print("\n   [Bob] Processing ClientHello...")
        print("   [Bob] Verifying Alice's certificate against CA...")
        server_response = secure_server.handle_client_request(client_hello)
        
        if not server_response.get("success"):
            print(f"\n   ✗ Handshake FAILED: {server_response.get('error')}")
            return
        
        print(f"   [Bob] Client verified: {server_response.get('client_verified')}")
        
        # Show encrypted session key
        encrypted_session_key_hex = server_response.get("encrypted_session_key")
        encrypted_session_key = bytes.fromhex(encrypted_session_key_hex)
        print("\n   [Bob → Alice] ServerHello with encrypted session key:")
        format_bytes_display(encrypted_session_key, "Encrypted Session Key (for Alice's eyes only):")
        
        # Alice verifies Bob's certificate and decrypts session key
        print("\n   [Alice] Processing ServerHello...")
        handshake_result = secure_client.complete_mutual_handshake(server_response)
        
        if not handshake_result.get("success"):
            print(f"\n   ✗ Handshake FAILED: {handshake_result.get('error')}")
            return
        
        session_key = handshake_result.get("session_key")
        print("\n   [Alice] Decrypted Session Key:")
        format_bytes_display(session_key, "Session Key (shared secret):")
        print("\n   ✓ Mutual TLS Handshake Complete!")
        print("   ✓ Both parties verified via CA - MITM attack prevented!")

        # ============================================================
        # STEP 6: Encrypted Message Exchange
        # ============================================================
        print("\n" + "─" * 70)
        print("STEP 6: Encrypted Message Exchange")
        print("─" * 70)
        
        # Alice sends encrypted message to Bob
        plaintext_alice = "Hello Bob! This is Alice. Our channel is secure! 🔐"
        print(f"\n   [Alice] Original message:")
        print(f"   \"{plaintext_alice}\"")
        
        # Encrypt message
        encrypted_message_alice = secure_client.channel.encrypt_message(plaintext_alice)
        print(f"\n   [Alice → Bob] Encrypted message:")
        format_bytes_display(encrypted_message_alice, "Ciphertext (unreadable to attackers):")
        
        # Build request (no need to pass encrypted_session_key in mutual TLS flow)
        client_request = secure_client.send_encrypted_message(plaintext_alice)
        
        # Bob receives and decrypts
        print("\n   [Bob] Receiving encrypted message...")
        server_response = secure_server.handle_client_request(client_request)
        
        if not server_response.get("success"):
            print(f"\n   ✗ Message processing FAILED: {server_response.get('error')}")
            return
        
        # Show Bob's encrypted response
        encrypted_response_hex = server_response.get("encrypted_message")
        encrypted_response = bytes.fromhex(encrypted_response_hex)
        print(f"\n   [Bob → Alice] Encrypted response:")
        format_bytes_display(encrypted_response, "Ciphertext (Bob's reply):")
        
        # Alice decrypts Bob's response
        decrypted_response = secure_client.receive_encrypted_message(server_response)
        print(f"\n   [Alice] Decrypted response from Bob:")
        print(f"   \"{decrypted_response}\"")

        # ============================================================
        # STEP 7: Summary
        # ============================================================
        print("\n" + "─" * 70)
        print("STEP 7: Communication Summary")
        print("─" * 70)
        print("""
   ┌─────────────────────────────────────────────────────────────────┐
   │                    SECURE CHANNEL ESTABLISHED                   │
   ├─────────────────────────────────────────────────────────────────┤
   │  1. Alice's certificate issued by CA during user creation      │
   │  2. Bob's certificate issued by CA during user creation        │
   │  3. Alice sent her certificate → Bob verified against CA       │
   │  4. Bob sent his certificate → Alice verified against CA       │
   │  5. Session key created only AFTER mutual verification         │
   │  6. All messages encrypted with shared session key             │
   ├─────────────────────────────────────────────────────────────────┤
   │  ✓ Man-in-the-Middle Attack: PREVENTED                         │
   │  ✓ Certificate validation: BOTH PARTIES VERIFIED               │
   │  ✓ Session key: SECURELY EXCHANGED                             │
   │  ✓ Messages: ENCRYPTED END-TO-END                              │
   └─────────────────────────────────────────────────────────────────┘
        """)
        
        if plaintext_alice in decrypted_response:
            print("   ✓ SUCCESS: Alice's message was received and echoed by Bob!")
        else:
            print("   ! Communication completed but echo check inconclusive")

    finally:
        print("\n" + "─" * 70)
        print(f"Demo finished. CA data preserved in: {demo_ca_dir}")
        print("─" * 70)


if __name__ == "__main__":
    demo_alice_bob_comm()
