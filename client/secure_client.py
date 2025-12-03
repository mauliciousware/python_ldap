"""
Secure Client

This module provides a secure client that handles certificate verification
and encrypted communication with the server using mutual TLS authentication.
"""

from typing import Dict, Optional
from auth.secure_communication import SecureChannel, SecureHandshake


class SecureClient:
    """
    Secure client that communicates with the server using certificate-based
    authentication and encryption. Supports mutual TLS for MITM protection.
    """
    
    def __init__(self, ca_cert_pem: str, client_cert_pem: Optional[str] = None,
                 client_key_pem: Optional[str] = None):
        """
        Initialize secure client.
        
        Args:
            ca_cert_pem: CA certificate for verifying server certificates
            client_cert_pem: Client certificate for mutual authentication (optional)
            client_key_pem: Client private key for decryption (optional)
        """
        self.ca_cert_pem = ca_cert_pem
        self.client_cert_pem = client_cert_pem
        self.client_key_pem = client_key_pem
        self.channel: Optional[SecureChannel] = None
        self.server_cert_pem: Optional[str] = None
        self.session_key: Optional[bytes] = None
    
    def initiate_mutual_handshake(self) -> Dict:
        """
        Initiate mutual TLS handshake by sending client certificate.
        Server will verify our certificate before creating session key.
        
        Returns:
            Request dictionary to send to server
        """
        if not self.client_cert_pem:
            raise RuntimeError("Client certificate required for mutual authentication")
        
        return {
            "type": "mutual_handshake",
            "client_certificate": self.client_cert_pem
        }
    
    def complete_mutual_handshake(self, server_response: Dict) -> Dict:
        """
        Complete mutual TLS handshake by decrypting session key from server.
        
        Args:
            server_response: Server's mutual handshake response
            
        Returns:
            Result dictionary
        """
        try:
            if not server_response.get("success"):
                return {"success": False, "error": server_response.get("error")}
            
            if not server_response.get("client_verified"):
                return {"success": False, "error": "Server did not verify our certificate"}
            
            # Verify server certificate
            self.channel = SecureChannel(self.ca_cert_pem)
            server_cert = server_response.get("server_certificate")
            if not self.channel.verify_certificate(server_cert):
                return {"success": False, "error": "Server certificate verification failed"}
            
            self.server_cert_pem = server_cert
            print("   [Client] Server certificate verified against CA ✓")
            
            # Decrypt session key with our private key
            encrypted_session_key_hex = server_response.get("encrypted_session_key")
            encrypted_session_key = bytes.fromhex(encrypted_session_key_hex)
            
            self.session_key = self.channel.decrypt_session_key(
                self.client_key_pem, 
                encrypted_session_key
            )
            self.channel.session_key = self.session_key
            
            return {
                "success": True,
                "session_key": self.session_key,
                "message": "Mutual authentication successful. Secure channel established."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def initiate_handshake(self, server_response: Dict) -> Dict:
        """
        Initiate handshake with server.
        
        Args:
            server_response: Server handshake response
            
        Returns:
            Client handshake result
        """
        try:
            # Perform client handshake
            handshake_result = SecureHandshake.client_handshake(
                self.ca_cert_pem,
                server_response
            )
            
            self.channel = handshake_result["channel"]
            self.server_cert_pem = server_response.get("server_certificate")
            
            return {
                "success": True,
                "encrypted_session_key": handshake_result["encrypted_session_key"].hex()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def send_encrypted_message(self, message: str, encrypted_session_key: Optional[bytes] = None) -> Dict:
        """
        Send an encrypted message to the server.
        
        Args:
            message: Message to send
            encrypted_session_key: Encrypted session key (optional for mutual TLS flow)
            
        Returns:
            Request dictionary ready to send to server
        """
        if not self.channel:
            raise RuntimeError("Handshake not completed. Call initiate_handshake() first.")
        
        # Encrypt message using the channel's session key
        encrypted_message = self.channel.encrypt_message(message)
        
        request = {
            "type": "encrypted_message",
            "encrypted_message": encrypted_message.hex()
        }
        
        # Include encrypted session key if provided (for non-mutual auth flow)
        if encrypted_session_key:
            request["encrypted_session_key"] = encrypted_session_key.hex()
        
        return request
    
    def receive_encrypted_message(self, encrypted_response: Dict) -> str:
        """
        Decrypt a message from the server.
        
        Args:
            encrypted_response: Server response with encrypted message
            
        Returns:
            Decrypted message
        """
        if not self.channel:
            raise RuntimeError("Handshake not completed")
        
        encrypted_message_hex = encrypted_response.get("encrypted_message")
        if not encrypted_message_hex:
            raise ValueError("No encrypted message in response")
        
        encrypted_message = bytes.fromhex(encrypted_message_hex)
        decrypted_message = self.channel.decrypt_message(encrypted_message)
        
        return decrypted_message
    
    def verify_server_certificate(self, server_cert_pem: str) -> bool:
        """
        Verify server certificate against CA.
        
        Args:
            server_cert_pem: Server certificate in PEM format
            
        Returns:
            True if certificate is valid
        """
        channel = SecureChannel(self.ca_cert_pem)
        return channel.verify_certificate(server_cert_pem)
    
    def request_server_certificate(self) -> Dict:
        """
        Request server certificate (for handshake initiation).
        
        Returns:
            Request dictionary
        """
        return {
            "type": "handshake",
            "action": "request_certificate"
        }

