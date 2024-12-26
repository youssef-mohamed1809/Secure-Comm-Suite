from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify
import hashlib

class AESCryptography:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
    def aes_encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        ciphertext = cipher.encrypt(plaintext.encode()) 
        return ciphertext

    def aes_decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()

def rsa_encrypt(key, data):
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted = cipher_rsa.encrypt(data)
    return encrypted
    
def rsa_decrypt(key, data):
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted = cipher_rsa.decrypt(data)
    return decrypted

def sha_256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# print(type(sha_256_hash("sui")))
# two = sha_256_hash("suii")


