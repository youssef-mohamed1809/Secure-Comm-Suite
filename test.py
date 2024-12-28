import unittest
import base64
from Crypto.PublicKey import RSA
import struct

from KeyManagerServer.Authentication import login, create_account
from KeyManagerServer.Cryptography import sha_256_hash, generate_rsa_keys, rsa_decrypt, rsa_encrypt, generate_aes_key_and_nonce, create_signature, verify_signature, AESCryptography

class SecureCommSuiteTest(unittest.TestCase):
    def test_hash(self):
        acctual_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        predicted_hash = sha_256_hash("hello").hexdigest()
        self.assertEqual(acctual_hash, predicted_hash, "Hashes are not equal")
        
    def test_RSA_encryption_decryption(self):
        msg = "Hello"
        private_key, public_key = generate_rsa_keys()
        
        public_key = base64.b64decode(public_key.strip())
        public_key =  RSA.import_key(public_key)
        
        private_key = base64.b64decode(private_key.strip())
        private_key =  RSA.import_key(private_key)

        
        encrypted_msg = rsa_encrypt(public_key, msg.encode())
        decrypted_msg = rsa_decrypt(private_key, encrypted_msg)
        
        self.assertEqual(msg, decrypted_msg.decode())
        
    def test_AES_encryption_decryption(self):
        msg = "Hello"
        key, nonce = generate_aes_key_and_nonce()
        nonce_bytes = struct.pack('<Q', nonce)

        aesCryptography = AESCryptography(key.encode(), nonce_bytes)
        encrypted_message = aesCryptography.aes_encrypt(msg)
        decrypted_message = aesCryptography.aes_decrypt(encrypted_message)
        
        self.assertEqual(msg, decrypted_message)        
           
    def test_create_account_login(self):
        username = "Mohamed1"
        password = "123456"
        create_account(username, password, "")
        loggedIn = login(username, password)
        self.assertTrue(loggedIn)
    
    def test_failed_login(self):
        username = "Mohamed"
        # Incorrect password
        password = "hello"
        
        loggedIn = login(username, password)
        self.assertFalse(loggedIn)
        
    def test_digital_signature(self):
        msg = "Hello"
        hash_msg = sha_256_hash(msg)
        
        private_key, public_key = generate_rsa_keys()
        
        public_key = base64.b64decode(public_key.strip())
        public_key =  RSA.import_key(public_key)
        
        private_key = base64.b64decode(private_key.strip())
        private_key =  RSA.import_key(private_key)
        
        signature = create_signature(private_key, hash_msg)
        
        signatureVerified = verify_signature(public_key, signature, hash_msg)
        self.assertTrue(signatureVerified)
        
        
        
             
if __name__ == '__main__':
    unittest.main()


