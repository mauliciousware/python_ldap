"""
Secure Server

This module provides a secure server that handles certificate-based
authentication and encrypted communication.
"""

from typing import Dict, Optional
from cryptography.hazmat.primitives import serialization
from auth.secure_communication import SecureChannel, SecureHandshake
from ca.certificate_authority import CertificateAuthority
from server.ldap_server import LDAPServer


class SecureServer:
    """
    Secure server that handles certificate-based authentication
    and encrypted communication.
    """
    
    def __init__(self, server_name: str, ca: CertificateAuthority,
                ldap_server: LDAPServer, server_key_pem: str):
        """
        Initialize secure server.
        
        Args:
            server_name: Server name/identifier
            ca: Certificate Authority instance
            ldap_server: LDAP server instance
            server_key_pem: Server private key in PEM format
        """
        self.server_name = server_name
        self.ca = ca
        self.ldap_server = ldap_server
        self.server_key_pem = server_key_pem
        self.ca_cert_pem = ca.get_ca_certificate()
        
        # Get server certificate
        self.server_cert_pem = self._get_server_certificate()
    
    def _get_server_certificate(self) -> str:
        """Get or create server certificate."""
        # Try to get certificate from LDAP
        cert_data = self.ldap_server.get_certificate(self.server_name)
        
        if cert_data:
            # Certificate exists, load it
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            return cert.public_bytes(serialization.Encoding.PEM).decode()
        else:
            # If certificate doesn't exist in LDAP, we'll need to create it
            # This is a simplified case - in production, certificate should be created during setup
            # For now, we'll generate a temporary certificate
            from ca.cert_manager import CertificateManager
            
            # Generate CSR
            csr_pem, _, _ = CertificateManager.generate_csr(self.server_name)
            
            # Sign certificate
            cert_pem, _ = self.ca.sign_csr(csr_pem, self.server_name, cert_type="server")
            
            # Store in LDAP
            cert_der = CertificateManager.certificate_to_der(cert_pem)
            self.ldap_server.directory.add_certificate_entry(self.server_name, cert_der)
            
            return cert_pem
    
    def handle_client_request(self, client_request: Dict) -> Dict:
        """
        Handle a client request with secure communication.
        
        Args:
            client_request: Client request dictionary
            
        Returns:
            Response dictionary
        """
        request_type = client_request.get("type")
        
        if request_type == "handshake":
            return self._handle_handshake(client_request)
        
        elif request_type == "encrypted_message":
            return self._handle_encrypted_message(client_request)
        
        else:
            return {"success": False, "error": f"Unknown request type: {request_type}"}
    
    def _handle_handshake(self, request: Dict) -> Dict:
        """Handle client handshake request."""
        try:
            # Perform server handshake
            handshake_result = SecureHandshake.server_handshake(
                self.server_cert_pem,
                self.server_key_pem,
                self.ca_cert_pem
            )
            
            return {
                "success": True,
                "type": "handshake_response",
                "server_certificate": handshake_result["server_certificate"],
                "server_public_key": handshake_result["server_public_key"],
                "session_key": handshake_result["session_key"].hex()  # Convert to hex for JSON
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _handle_encrypted_message(self, request: Dict) -> Dict:
        """Handle encrypted message from client."""
        try:
            encrypted_key_hex = request.get("encrypted_session_key")
            encrypted_message_hex = request.get("encrypted_message")
            
            if not encrypted_key_hex or not encrypted_message_hex:
                return {"success": False, "error": "Missing encrypted data"}
            
            # Decrypt session key
            from auth.secure_communication import SecureChannel
            channel = SecureChannel(self.ca_cert_pem)
            encrypted_key = bytes.fromhex(encrypted_key_hex)
            session_key = channel.decrypt_session_key(self.server_key_pem, encrypted_key)
            
            # Decrypt message
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            decrypted_message = channel.decrypt_message(encrypted_message, session_key)
            
            # Process the decrypted message (parse as JSON or simple command)
            # For simplicity, we'll echo it back
            response_message = f"Server received: {decrypted_message}"
            
            # Encrypt response
            encrypted_response = channel.encrypt_message(response_message, session_key)
            
            return {
                "success": True,
                "type": "encrypted_response",
                "encrypted_message": encrypted_response.hex()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def send_certificate(self) -> Dict:
        """
        Send certificate and public key to client (for handshake).
        
        Returns:
            Dictionary with certificate and public key
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        cert = x509.load_pem_x509_certificate(
            self.server_cert_pem.encode(), default_backend()
        )
        public_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return {
            "certificate": self.server_cert_pem,
            "public_key": public_key_pem
        }

