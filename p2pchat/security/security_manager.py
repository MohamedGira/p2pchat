from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import os
from threading import Lock


class SecurityManager:
    """
    Singleton class to handle all security operations including key management,
    encryption/decryption, and message authentication.
    """

    _instance = None
    _lock = Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(SecurityManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.symmetric_key = None
            self.private_key = None
            self.public_key = None
            self.fernet = None
            self._initialize_keys()
            self._initialized = True
            self.default_padding = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            

    def reset(self):
        self.symmetric_key = None
        self.private_key = None
        self.public_key = None
        self.fernet = None
        self._initialize_keys()
        self._initialized = True

    def _initialize_keys(self):
        """Initialize both symmetric and asymmetric keys"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.symmetric_key = Fernet.generate_key()
        self.fernet = Fernet(self.symmetric_key)

    def _calculate_hash(self, data: bytes) -> bytes:
        """Calculate SHA-256 hash of data"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    def get_public_key_bytes(self):
        """Export public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def encrypt_message(self, message: str) -> dict:
        """
        Encrypt a message using symmetric encryption.
        Returns a dictionary with the encrypted message, its signature, and hash.
        """
        message_bytes = message.encode()
        encrypted_message = self.fernet.encrypt(message_bytes)

        # Calculate hash of original message
        message_hash = self._calculate_hash(message_bytes)

        # Create digital signature
        signature = self.private_key.sign(
            encrypted_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        return {
            "message": base64.b64encode(encrypted_message).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8"),
            "hash": base64.b64encode(message_hash).decode("utf-8"),
        }

    def decrypt_message(
        self, encrypted_data: dict, sender_public_key_bytes: bytes
    ) -> str:
        """
        Decrypt a message and verify its signature and hash using the sender's public key.
        """
        try:
            encrypted_message = base64.b64decode(encrypted_data["message"])
            signature = base64.b64decode(encrypted_data["signature"])
            original_hash = base64.b64decode(encrypted_data["hash"])

            # Load sender's public key
            sender_public_key = serialization.load_pem_public_key(
                sender_public_key_bytes
            )

            # Verify signature
            sender_public_key.verify(
                signature,
                encrypted_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            # Decrypt message
            decrypted_message = KeyExchange().peer_fernet.decrypt(encrypted_message)

            # Verify hash
            computed_hash = self._calculate_hash(decrypted_message)
            if not computed_hash == original_hash:
                raise ValueError("Message integrity check failed: hash mismatch")

            return decrypted_message.decode()

        except Exception as e:
            raise ValueError(f"connection attempted")


class KeyExchange:
    """
    Singleton class to handle secure key exchange between clients.
    """

    _instance = None
    _lock = Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                # Double-checked locking pattern
                if cls._instance is None:
                    cls._instance = super(KeyExchange, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.peer_public_key = None
            self.peer_public_key_bytes = None
            self.peer_fernet_key = None
            self.peer_fernet = None
            self._initialized = True

    def reset(self):
        self.peer_public_key = None
        self.peer_public_key_bytes = None
        self.peer_fernet_key = None
        self.peer_fernet = None
        self._initialized = True

    def initiate_exchange(self) -> bytes:
        """
        Initiate key exchange by sending public key
        """
        return SecurityManager().get_public_key_bytes()

    def complete_exchange(
        self, peer_public_key_bytes: bytes = None, encrypted_fernet_key: bytes = None
    ) -> bool:
        """
        Complete the key exchange by processing peer's public key
        """
        # Store peer's public key for future message verification
        if peer_public_key_bytes is not None:
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key_bytes
            )
            self.peer_public_key_bytes = peer_public_key_bytes
        if encrypted_fernet_key is not None:
            self.peer_fernet_key = self.decrypt_fernet_key(encrypted_fernet_key)
            self.peer_fernet = Fernet(self.peer_fernet_key)
            self.setup_peer_fernet(self.peer_fernet_key)

        return True

    def setup_peer_fernet(self, fernet_key):
        self.peer_fernet_key = fernet_key
        self.peer_fernet = Fernet(self.peer_fernet_key)
        SecurityManager().symmetric_key = fernet_key
        SecurityManager().fernet = self.peer_fernet

    def encrypt_fernet_key(self, fernet_key: bytes) -> bytes:
        """Encrypt Fernet key using peer's public key"""
        if isinstance(KeyExchange().peer_public_key, bytes):
            KeyExchange().peer_public_key = serialization.load_pem_public_key(
                KeyExchange().peer_public_key
            )

        encrypted_key = KeyExchange().peer_public_key.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return encrypted_key

    def decrypt_fernet_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt Fernet key using own private key"""
        decrypted_key = SecurityManager().private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_key
