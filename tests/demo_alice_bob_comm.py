import sys
import os
import shutil

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager
from ldap.directory import DirectoryService
from server.ldap_server import LDAPServer
from server.secure_server import SecureServer
from client.secure_client import SecureClient


def demo_alice_bob_comm():
    print("=== Alice  Bob Secure Communication Demo ===")

    demo_ca_dir = "demo_ca_alice_bob"
    if os.path.exists(demo_ca_dir):
        shutil.rmtree(demo_ca_dir)

    os.makedirs(demo_ca_dir, exist_ok=True)

    try:
        # 1. Shared CA
        print("\n[1] Initializing shared Certificate Authority (CA)...")
        ca = CertificateAuthority(ca_dir=demo_ca_dir)
        ca.initialize()
        print(f"   CA directory: {demo_ca_dir}")

        # 2. Shared Directory + LDAP Server
        print("\n[2] Starting shared DirectoryService and LDAPServer...")
        directory = DirectoryService()
        ldap_server = LDAPServer(directory, ca=ca)

        # 3. Create Alice and Bob in same directory
        print("\n[3] Creating users Alice and Bob in LDAP...")
        alice_username = "alice"
        bob_username = "bob"

        directory.add_user(
            alice_username,
            {"email": "alice@example.com", "full_name": "Alice Smith"},
            password="alice_password",
        )
        directory.add_user(
            bob_username,
            {"email": "bob@example.com", "full_name": "Bob Jones"},
            password="bob_password",
        )
        print("   Users created: alice, bob")

        # 4. Issue certificates for Alice and Bob via same CA
        print("\n[4] Issuing certificates for Alice and Bob via shared CA...")

        # Alice CSR + cert (generate_csr returns: csr_pem, private_key_object, private_key_pem)
        csr_pem_alice, _, alice_priv_key_pem = CertificateManager.generate_csr(alice_username)
        cert_pem_alice, _ = ca.sign_csr(csr_pem_alice, alice_username, cert_type="client")

        # Bob CSR + cert (used as server cert)
        csr_pem_bob, _, bob_priv_key_pem = CertificateManager.generate_csr(bob_username)
        cert_pem_bob, _ = ca.sign_csr(csr_pem_bob, bob_username, cert_type="server")

        # Store Bob's certificate in LDAP so SecureServer finds it (key match)
        cert_der_bob = CertificateManager.certificate_to_der(cert_pem_bob)
        directory.add_certificate_entry(bob_username, cert_der_bob)

        print("   Certificates issued for: alice (client), bob (server)")

        # 5. Start secure server for Bob
        print("\n[5] Starting SecureServer for Bob (acts as server)...")
        # SecureServer expects: server_name, ca, ldap_server, server_key_pem (PEM string)
        secure_server = SecureServer(
            server_name=bob_username,
            ca=ca,
            ldap_server=ldap_server,
            server_key_pem=bob_priv_key_pem,
        )

        # 6. Alice acts as secure client and performs handshake with Bob
        print("\n[6] Alice (client) establishing secure channel to Bob (server)...")
        secure_client = SecureClient(ca_cert_pem=ca.get_ca_certificate())

        # Step 1: Alice requests Bob's certificate (handshake request)
        client_hello = secure_client.request_server_certificate()
        print("   Alice -> Bob: handshake request:", client_hello)

        # Step 2: Bob handles handshake and sends back certificate + session key info
        server_handshake_response = secure_server.handle_client_request({"type": "handshake"})
        print("   Bob -> Alice: handshake response (truncated):",
              {k: (v[:60] + "...") if isinstance(v, str) and len(v) > 60 else v
               for k, v in server_handshake_response.items()})

        if not server_handshake_response.get("success"):
            print("\n[!] Handshake failed at server side:", server_handshake_response.get("error"))
            return

        # Step 3: Alice validates server cert and builds channel
        handshake_result = secure_client.initiate_handshake(server_handshake_response)
        if not handshake_result.get("success"):
            print("\n[!] Handshake failed at client side:", handshake_result.get("error"))
            return

        encrypted_session_key_hex = handshake_result["encrypted_session_key"]
        print("   Alice: encrypted session key (hex, truncated):",
              encrypted_session_key_hex[:60] + "...")

        # 7. Send encrypted message from Alice to Bob
        print("\n[7] Sending encrypted message from Alice to Bob...")
        plaintext = "Hello Bob, this is Alice talking over a secure channel!"

        client_encrypted_request = secure_client.send_encrypted_message(
            message=plaintext,
            encrypted_session_key=bytes.fromhex(encrypted_session_key_hex),
        )

        print("   Alice -> Bob: encrypted request (type, lengths):",
              {
                  "type": client_encrypted_request["type"],
                  "len(encrypted_session_key)": len(client_encrypted_request["encrypted_session_key"]),
                  "len(encrypted_message)": len(client_encrypted_request["encrypted_message"]),
              })

        # Bob decrypts the message and responds
        server_encrypted_response = secure_server.handle_client_request(client_encrypted_request)
        if not server_encrypted_response.get("success"):
            print("\n[!] Server failed to process encrypted message:",
                  server_encrypted_response.get("error"))
            return

        print("   Bob -> Alice: encrypted response (len):",
              len(server_encrypted_response.get("encrypted_message", "")))

        # Alice decrypts server's response
        decrypted_response = secure_client.receive_encrypted_message(server_encrypted_response)

        print("\n   Original message from Alice :", plaintext)
        print("   Decrypted response at Alice:", decrypted_response)

        if plaintext in decrypted_response:
            print("\n[✓] Secure communication successful: Alice's message was received and echoed by Bob.")
        else:
            print("\n[!] Secure communication might have failed: response does not contain original message.")

    finally:
        print("\n[Cleanup] Demo finished. CA data kept in:", demo_ca_dir)
        # If you want automatic cleanup instead, uncomment below:
        # if os.path.exists(demo_ca_dir):
        #     shutil.rmtree(demo_ca_dir)


if __name__ == "__main__":
    demo_alice_bob_comm()
