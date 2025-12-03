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

def demo_bob():
    print("Setting up test environment for Bob...")
    test_ca_dir = "demo_ca_bob"
    # if os.path.exists(test_ca_dir):
    #     shutil.rmtree(test_ca_dir)
    try:
        # Initialize CA
        ca = CertificateAuthority(ca_dir=test_ca_dir)
        ca.initialize()
        # Initialize Server
        directory = DirectoryService()
        server = LDAPServer(directory, ca=ca)
        # --- User: Bob ---
        username_bob = "bob"
        user_role_bob = RegularUser(username_bob)
        client_bob = LDAPClient(server, user_role_bob)
        print(f"Creating user '{username_bob}' in LDAP...")
        server.add_user(username_bob, {"email": "bob@example.com"}, "password123")
        print(f"Generating CSR for user '{username_bob}'...")
        csr_pem_bob, _, _ = CertificateManager.generate_csr(username_bob)
        print(f"Requesting certificate for '{username_bob}'...")
        response_bob = client_bob.request_certificate(username_bob, csr_pem_bob)
        if response_bob["success"]:
            print(f"Success! Status: {response_bob.get('status')}")
            print(f"Certificate saved to {test_ca_dir}/certs/{username_bob}.crt")
        else:
            print(f"Failed: {response_bob.get('error')}")
        # --- Additional Test: Re-request certificate for Bob (should already exist) ---
        print("\n--- Re-requesting certificate for Bob (should already exist) ---")
        print(f"Generating CSR for user '{username_bob}' again...")
        csr_pem_bob_2, _, _ = CertificateManager.generate_csr(username_bob)
        print(f"Requesting certificate for '{username_bob}' again...")
        response_bob_2 = client_bob.request_certificate(username_bob, csr_pem_bob_2)
        if response_bob_2["success"]:
            print(f"Unexpected Success! Status: {response_bob_2.get('status')}")
        else:
            print(f"Expected failure: {response_bob_2.get('error')}")
        print("\nDemo for Bob completed successfully.")
    finally:
        print("Cleaning up test environment...")
    #     if os.path.exists(test_ca_dir):
    #         shutil.rmtree(test_ca_dir)

if __name__ == "__main__":
    demo_bob()
