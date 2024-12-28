from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random
import base64
import string

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

def generate_aes_key_and_nonce():
    key = ''.join(random.choices(string.ascii_letters, k=16))
    nonce = random.randint(1, 10000)
    return key, nonce

def generate_rsa_keys():
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    private_key_b64 = base64.b64encode(private_key).decode('utf-8')
    public_key_b64 = base64.b64encode(public_key).decode('utf-8')
    return private_key_b64, public_key_b64

def rsa_encrypt(key, data):
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted = cipher_rsa.encrypt(data)
    return encrypted
    
def rsa_decrypt(key, data):
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted = cipher_rsa.decrypt(data)
    return decrypted

def sha_256_hash(data):
    return SHA256.new(data.encode())


def create_signature(private_key, hash):
    return pkcs1_15.new(private_key).sign(hash)

def verify_signature(public_key, signature, myhash):
    try:
        pkcs1_15.new(public_key).verify(myhash, signature)
        return True
    except:
           return False





