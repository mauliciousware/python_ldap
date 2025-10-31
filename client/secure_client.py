"""
Secure Client

This module provides a secure client that handles certificate verification
and encrypted communication with the server.
"""

from typing import Dict, Optional
from auth.secure_communication import SecureChannel, SecureHandshake


class SecureClient:
    """
    Secure client that communicates with the server using certificate-based
    authentication and encryption.
    """
    
    def __init__(self, ca_cert_pem: str):
        """
        Initialize secure client.
        
        Args:
            ca_cert_pem: CA certificate for verifying server certificates
        """
        self.ca_cert_pem = ca_cert_pem
        self.channel: Optional[SecureChannel] = None
        self.server_cert_pem: Optional[str] = None
    
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
    
    def send_encrypted_message(self, message: str, encrypted_session_key: bytes) -> Dict:
        """
        Send an encrypted message to the server.
        
        Args:
            message: Message to send
            encrypted_session_key: Encrypted session key
            
        Returns:
            Request dictionary ready to send to server
        """
        if not self.channel:
            raise RuntimeError("Handshake not completed. Call initiate_handshake() first.")
        
        # Encrypt message
        # Note: In a real implementation, we'd use the session key from handshake
        # For this simulation, we'll use the channel's session key
        encrypted_message = self.channel.encrypt_message(message)
        
        return {
            "type": "encrypted_message",
            "encrypted_session_key": encrypted_session_key.hex(),
            "encrypted_message": encrypted_message.hex()
        }
    
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

