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

def test_certificate_issuance():
    print("Setting up test environment...")
    test_ca_dir = "test_ca"
    if os.path.exists(test_ca_dir):
        shutil.rmtree(test_ca_dir)
    
    try:
        # Initialize CA
        ca = CertificateAuthority(ca_dir=test_ca_dir)
        ca.initialize()
        
        # Initialize Server
        directory = DirectoryService()
        server = LDAPServer(directory, ca=ca)
        
        # Initialize Client
        username = "alice"
        user_role = RegularUser(username)
        client = LDAPClient(server, user_role)
        
        print(f"Generating CSR for user '{username}'...")
        csr_pem, _, _ = CertificateManager.generate_csr(username)
        
        print("Requesting certificate (First time)...")
        response = client.request_certificate(username, csr_pem)
        
        if not response["success"]:
            print(f"FAILED: {response.get('error')}")
            return
        
        cert1 = response["certificate"]
        status1 = response.get("status")
        print(f"Success! Status: {status1}")
        
        if status1 != "new":
            print("FAILED: Expected status 'new' for first request")
            return

        print("Requesting certificate (Second time)...")
        response = client.request_certificate(username, csr_pem)
        
        if not response["success"]:
            print(f"FAILED: {response.get('error')}")
            return
            
        cert2 = response["certificate"]
        status2 = response.get("status")
        print(f"Success! Status: {status2}")
        
        if status2 != "existing":
            print("FAILED: Expected status 'existing' for second request")
            return
            
        if cert1 != cert2:
            print("FAILED: Certificates do not match!")
            return
            
        print("VERIFICATION PASSED: Certificate issuance and retrieval works as expected.")
        
    finally:
        # Cleanup
        if os.path.exists(test_ca_dir):
            shutil.rmtree(test_ca_dir)

if __name__ == "__main__":
    test_certificate_issuance()
