"""
Secure Communication Module

This module simulates TLS/SSL-like secure communication:
- Certificate exchange
- Session key generation and encryption
- Secure message encryption/decryption
"""

import secrets
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509


class SecureChannel:
    """
    Simulates a secure communication channel using certificate-based
    authentication and session key encryption.
    """
    
    def __init__(self, ca_cert_pem: str):
        """
        Initialize secure channel with CA certificate.
        
        Args:
            ca_cert_pem: PEM-encoded CA certificate for verification
        """
        self.ca_cert = x509.load_pem_x509_certificate(
            ca_cert_pem.encode(), default_backend()
        )
        self.session_key: Optional[bytes] = None
        self.peer_cert: Optional[x509.Certificate] = None
    
    def verify_certificate(self, cert_pem: str) -> bool:
        """
        Verify a certificate against the CA.
        
        Args:
            cert_pem: PEM-encoded certificate
            
        Returns:
            True if certificate is valid
        """
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            
            # Verify signature
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Check validity period
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
                return False
            
            self.peer_cert = cert
            return True
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            return False
    
    def generate_session_key(self) -> bytes:
        """
        Generate a random session key for symmetric encryption.
        
        Returns:
            32-byte session key
        """
        self.session_key = secrets.token_bytes(32)
        return self.session_key
    
    def encrypt_session_key(self, public_key_pem: str, session_key: bytes) -> bytes:
        """
        Encrypt session key with peer's public key.
        
        Args:
            public_key_pem: PEM-encoded public key or certificate
            session_key: Session key to encrypt
            
        Returns:
            Encrypted session key
        """
        # Extract public key from certificate if needed
        if isinstance(public_key_pem, str) and "BEGIN CERTIFICATE" in public_key_pem:
            cert = x509.load_pem_x509_certificate(
                public_key_pem.encode(), default_backend()
            )
            public_key = cert.public_key()
        else:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(), default_backend()
            )
        
        # Encrypt session key
        encrypted = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted
    
    def decrypt_session_key(self, private_key_pem: str, encrypted_key: bytes) -> bytes:
        """
        Decrypt session key with private key.
        
        Args:
            private_key_pem: PEM-encoded private key
            encrypted_key: Encrypted session key
            
        Returns:
            Decrypted session key
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend()
        )
        
        session_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.session_key = session_key
        return session_key
    
    def encrypt_message(self, message: str, session_key: Optional[bytes] = None) -> bytes:
        """
        Encrypt a message using AES encryption.
        
        Args:
            message: Message to encrypt
            session_key: Session key (uses stored key if None)
            
        Returns:
            Encrypted message (IV + ciphertext)
        """
        if session_key is None:
            if self.session_key is None:
                raise RuntimeError("No session key available")
            session_key = self.session_key
        
        # Generate IV
        iv = secrets.token_bytes(16)
        
        # Encrypt message
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad message to block size
        message_bytes = message.encode()
        pad_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([pad_length] * pad_length)
        
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt_message(self, encrypted_data: bytes, session_key: Optional[bytes] = None) -> str:
        """
        Decrypt a message using AES decryption.
        
        Args:
            encrypted_data: Encrypted data (IV + ciphertext)
            session_key: Session key (uses stored key if None)
            
        Returns:
            Decrypted message
        """
        if session_key is None:
            if self.session_key is None:
                raise RuntimeError("No session key available")
            session_key = self.session_key
        
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        pad_length = padded_message[-1]
        message = padded_message[:-pad_length]
        
        return message.decode()


class SecureHandshake:
    """
    Simulates a TLS-like handshake process with mutual authentication.
    Prevents man-in-the-middle attacks by verifying both client and server certificates.
    """
    
    @staticmethod
    def server_handshake(server_cert_pem: str, server_key_pem: str,
                        ca_cert_pem: str, client_cert_pem: Optional[str] = None) -> dict:
        """
        Perform server-side handshake with optional client certificate verification.
        
        Args:
            server_cert_pem: Server certificate
            server_key_pem: Server private key
            ca_cert_pem: CA certificate
            client_cert_pem: Optional client certificate for mutual auth
            
        Returns:
            Dictionary with handshake results
        """
        channel = SecureChannel(ca_cert_pem)
        
        # Verify server certificate
        if not channel.verify_certificate(server_cert_pem):
            raise ValueError("Server certificate verification failed")
        
        # If client certificate provided, verify it (mutual TLS)
        client_verified = False
        if client_cert_pem:
            client_verified = channel.verify_certificate(client_cert_pem)
            if not client_verified:
                raise ValueError("Client certificate verification failed - possible MITM attack!")
            print("   [Server] Client certificate verified against CA ✓")
        
        # Generate session key only after successful verification
        session_key = channel.generate_session_key()
        
        # Extract server public key from certificate
        server_cert = x509.load_pem_x509_certificate(
            server_cert_pem.encode(), default_backend()
        )
        server_public_key = server_cert.public_key()
        
        return {
            "server_certificate": server_cert_pem,
            "server_public_key": server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "session_key": session_key,
            "channel": channel,
            "client_verified": client_verified
        }
    
    @staticmethod
    def server_verify_client_and_create_session(ca_cert_pem: str, 
                                                  client_cert_pem: str,
                                                  server_key_pem: str) -> dict:
        """
        Server verifies client certificate and creates a session key for communication.
        This prevents man-in-the-middle attacks.
        
        Args:
            ca_cert_pem: CA certificate for verification
            client_cert_pem: Client certificate to verify
            server_key_pem: Server private key
            
        Returns:
            Dictionary with session info
        """
        channel = SecureChannel(ca_cert_pem)
        
        # Verify client certificate against CA
        if not channel.verify_certificate(client_cert_pem):
            raise ValueError("Client certificate verification FAILED - Rejecting connection!")
        
        print("   [Server] Client certificate verified against CA ✓")
        
        # Generate session key for secure communication
        session_key = channel.generate_session_key()
        
        # Extract client public key from certificate
        client_cert = x509.load_pem_x509_certificate(
            client_cert_pem.encode(), default_backend()
        )
        client_public_key = client_cert.public_key()
        
        # Encrypt session key with client's public key
        encrypted_session_key = channel.encrypt_session_key(client_cert_pem, session_key)
        
        return {
            "session_key": session_key,
            "encrypted_session_key": encrypted_session_key,
            "client_public_key": client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "channel": channel,
            "verified": True
        }
    
    @staticmethod
    def client_handshake(ca_cert_pem: str, server_response: dict) -> dict:
        """
        Perform client-side handshake.
        
        Args:
            ca_cert_pem: CA certificate for verification
            server_response: Server handshake response
            
        Returns:
            Dictionary with handshake results
        """
        channel = SecureChannel(ca_cert_pem)
        
        # Verify server certificate
        server_cert_pem = server_response["server_certificate"]
        if not channel.verify_certificate(server_cert_pem):
            raise ValueError("Server certificate verification failed")
        
        # Encrypt session key with server's public key
        server_public_key_pem = server_response["server_public_key"]
        session_key = server_response["session_key"]
        
        # Convert session key from hex string to bytes if needed
        if isinstance(session_key, str):
            session_key = bytes.fromhex(session_key)
        
        encrypted_session_key = channel.encrypt_session_key(
            server_public_key_pem,
            session_key
        )
        
        # Set session key on channel for later use
        channel.session_key = session_key
        
        return {
            "encrypted_session_key": encrypted_session_key,
            "channel": channel
        }

