import unittest
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import __init__
from security.security_manager import SecurityManager,KeyExchange
class TestSecurityManager(unittest.TestCase):
    def setUp(self):
        self.security_manager = SecurityManager()
        self.security_manager.reset()  # Ensure clean state
        self.test_message = "Hello, World!"

    def test_singleton_pattern(self):
        """Test that SecurityManager follows singleton pattern"""
        manager1 = SecurityManager()
        manager2 = SecurityManager()
        self.assertIs(manager1, manager2)

    def test_key_initialization(self):
        """Test that keys are properly initialized"""
        self.assertIsNotNone(self.security_manager.private_key)
        self.assertIsNotNone(self.security_manager.public_key)
        self.assertIsNotNone(self.security_manager.symmetric_key)
        self.assertIsNotNone(self.security_manager.fernet)

    def test_encrypt_decrypt_message(self):
        """Test message encryption and decryption"""
        # Setup key exchange
        key_exchange = KeyExchange()
        key_exchange.reset()
        
        # Get public key
        public_key_bytes = self.security_manager.get_public_key_bytes()
        
        # Complete key exchange
        key_exchange.complete_exchange(public_key_bytes)
        
        # Encrypt message
        encrypted_data = self.security_manager.encrypt_message(self.test_message)
        
        
        # Verify encrypted data structure
        self.assertIn('message', encrypted_data)
        self.assertIn('signature', encrypted_data)
        self.assertIn('hash', encrypted_data)
        # mock credentials
        KeyExchange().peer_public_key=self.security_manager.public_key
        KeyExchange().peer_fernet=self.security_manager.fernet
        
        # Decrypt message
        decrypted_message = self.security_manager.decrypt_message(
            encrypted_data,
            public_key_bytes
        )
        
        self.assertEqual(self.test_message, decrypted_message)

    def test_hash_calculation(self):
        """Test hash calculation consistency"""
        message_bytes = self.test_message.encode()
        hash1 = self.security_manager._calculate_hash(message_bytes)
        hash2 = self.security_manager._calculate_hash(message_bytes)
        self.assertEqual(hash1, hash2)

    def test_invalid_message_decryption(self):
        """Test decryption with tampered message"""
        # Setup key exchange
        key_exchange = KeyExchange()
        key_exchange.reset()
        public_key_bytes = self.security_manager.get_public_key_bytes()
        key_exchange.complete_exchange(public_key_bytes)
        
        # Encrypt original message
        encrypted_data = self.security_manager.encrypt_message(self.test_message)
        
        # Tamper with the encrypted message
        tampered_data = encrypted_data.copy()
        tampered_data['message'] = base64.b64encode(b'tampered_message').decode('utf-8')
        
        # Attempt to decrypt tampered message
        with self.assertRaises(ValueError):
            self.security_manager.decrypt_message(tampered_data, public_key_bytes)

class TestKeyExchange(unittest.TestCase):
    def setUp(self):
        self.key_exchange = KeyExchange()
        self.key_exchange.reset()
        self.security_manager = SecurityManager()
        self.security_manager.reset()

    def test_singleton_pattern(self):
        """Test that KeyExchange follows singleton pattern"""
        exchange1 = KeyExchange()
        exchange2 = KeyExchange()
        self.assertIs(exchange1, exchange2)

    def test_key_exchange_process(self):
        """Test complete key exchange process"""
        # Initiate exchange
        public_key_bytes = self.key_exchange.initiate_exchange()
        self.assertIsNotNone(public_key_bytes)
        
        # Verify public key format
        public_key = serialization.load_pem_public_key(public_key_bytes)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)
        
        # mock peer_public_keey
        KeyExchange().peer_public_key=public_key
        # Complete exchange
        fernet_key = Fernet.generate_key()
        encrypted_fernet_key = KeyExchange().encrypt_fernet_key(fernet_key)
        
        success = self.key_exchange.complete_exchange(
            peer_public_key_bytes=public_key_bytes,
            encrypted_fernet_key=encrypted_fernet_key
        )
        self.assertTrue(success)
        
        # Verify peer Fernet setup
        self.assertIsNotNone(self.key_exchange.peer_fernet)
        self.assertIsNotNone(self.key_exchange.peer_fernet_key)

    def test_fernet_key_encryption_decryption(self):
        """Test Fernet key encryption and decryption"""
        # Setup
        public_key_bytes = self.key_exchange.initiate_exchange()
        self.key_exchange.complete_exchange(peer_public_key_bytes=public_key_bytes)
        
        # Generate and encrypt Fernet key
        original_key = Fernet.generate_key()
        encrypted_key = self.key_exchange.encrypt_fernet_key(original_key)
        
        # Decrypt key
        decrypted_key = self.key_exchange.decrypt_fernet_key(encrypted_key)
        
        # Verify keys match
        self.assertEqual(original_key, decrypted_key)

if __name__ == '__main__':
    unittest.main()