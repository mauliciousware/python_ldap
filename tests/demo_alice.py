import sys
import os
import shutil

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ca.certificate_authority import CertificateAuthority
from ca.cert_manager import CertificateManager
from server.ldap_server import LDAPServer
from ldap.directory import DirectoryService
from client.ldap_client import LDAPClient
from auth.roles import RegularUser

def demo_alice():
    print("Setting up test environment for Alice...")
    test_ca_dir = "demo_ca_alice"
    if os.path.exists(test_ca_dir):
        shutil.rmtree(test_ca_dir)
    try:
        # Initialize CA
        ca = CertificateAuthority(ca_dir=test_ca_dir)
        ca.initialize()
        # Initialize Server
        directory = DirectoryService()
        server = LDAPServer(directory, ca=ca)
        # --- User: Alice ---
        username_alice = "alice"
        user_role_alice = RegularUser(username_alice)
        client_alice = LDAPClient(server, user_role_alice)
        print(f"Creating user '{username_alice}' in LDAP...")
        server.add_user(username_alice, {"email": "alice@example.com"}, "password123")
        print(f"Generating CSR for user '{username_alice}'...")
        csr_pem_alice, _, _ = CertificateManager.generate_csr(username_alice)
        print(f"Requesting certificate for '{username_alice}'...")
        response_alice = client_alice.request_certificate(username_alice, csr_pem_alice)
        if response_alice["success"]:
            print(f"Success! Status: {response_alice.get('status')}")
            print(f"Certificate saved to {test_ca_dir}/certs/{username_alice}.crt")
        else:
            print(f"Failed: {response_alice.get('error')}")
        # --- Additional Test: Re-request certificate for Alice (should already exist) ---
        print("\n--- Re-requesting certificate for Alice (should already exist) ---")
        print(f"Generating CSR for user '{username_alice}' again...")
        csr_pem_alice_2, _, _ = CertificateManager.generate_csr(username_alice)
        print(f"Requesting certificate for '{username_alice}' again...")
        response_alice_2 = client_alice.request_certificate(username_alice, csr_pem_alice_2)
        if response_alice_2["success"]:
            print(f"Unexpected Success! Status: {response_alice_2.get('status')}")
        else:
            print(f"Expected failure: {response_alice_2.get('error')}")
        print("\nDemo for Alice completed successfully.")
    finally:
        print("Cleaning up test environment...")
    #     if os.path.exists(test_ca_dir):
    #         shutil.rmtree(test_ca_dir)

if __name__ == "__main__":
    demo_alice()
