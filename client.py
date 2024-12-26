import socket
import random
import string
from Cryptography import sha_256_hash, rsa_decrypt, rsa_encrypt, AESCryptography
from Crypto.PublicKey import RSA
import base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import struct

# import Cryptography as Cryptography
# from ..key_manager.KeyManager import generate_rsa_keys


HOST = "127.0.0.1"  # The server's hostname or IP address
KEY_MANAGER_PORT = 65432  # The port used by the server
CHAT_SERVER_PORT = 65433

KEY_MANAGER_PUBLIC_KEY = ""
MY_PRIVATE_KEY = ""

AES_KEY = None
NONCE = None

if __name__ == "__main__":
    keyManagerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    keyManagerSocket.connect((HOST, KEY_MANAGER_PORT))
    
    auth_choice = input("Press 1 for login or 2 to create a new account: ")
    keyManagerSocket.sendall(auth_choice.encode())
    ack = "0"
    while ack == "0":
        username = input("Input Username: ")
        password = input("Input Password: ")
        msg = username + ":" + sha_256_hash(password)
        keyManagerSocket.sendall(msg.encode())
        ack = keyManagerSocket.recv(1024).decode()
    
    if auth_choice != "1":
        # private, public = generate_rsa_keys()
        # keyManagerSocket.send(public.encode())
        pass
    
    
    f = open(f"{username}_private.txt", "r")
    MY_PRIVATE_KEY = RSA.import_key(base64.b64decode(f.read().strip()))
    f.close()
    
    f = open("authority_public.txt", "r")
    KEY_MANAGER_PUBLIC_KEY = RSA.import_key(base64.b64decode(f.read().strip()))
    f.close()
        

    friend_username = input("Input the username of the person you want to talk to: ")
    
    keyManagerSocket.send(friend_username.encode())
    
    friend_public_key, signature = keyManagerSocket.recv(1024).decode().split(" ")
    friend_public_key_HASHED = SHA256.new(friend_public_key.encode())
    signature = base64.b64decode(signature)



    try:
        pkcs1_15.new(KEY_MANAGER_PUBLIC_KEY).verify(friend_public_key_HASHED, signature)
        print("SUIIII")
    except:
           print("LAAAAA")

    keyManagerSocket.close()
    
    chatServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chatServerSocket.connect((HOST, CHAT_SERVER_PORT))
    
    numOfServerConnections = chatServerSocket.recv(1024).decode()
    if(int(numOfServerConnections) == 0):
        AES_KEY = ''.join(random.choices(string.ascii_letters, k=16))
        NONCE = random.randint(1, 10000)
        msg = AES_KEY + " " + str(NONCE)
        
        friend_public_key =RSA.import_key(base64.b64decode(friend_public_key.strip()))
        
        enc_key = rsa_encrypt(friend_public_key, msg.encode())
        aes_key_and_nonce_hashed = SHA256.new(enc_key)
        signature = pkcs1_15.new(MY_PRIVATE_KEY).sign(aes_key_and_nonce_hashed)
        
        msg =  base64.b64encode(enc_key).decode('utf-8') + " " + base64.b64encode(signature).decode("UTF-8")
        
        chatServerSocket.send(msg.encode())
        
        nonce_bytes = struct.pack('<Q', NONCE)
        
        symm_crypt = AESCryptography(key=AES_KEY.encode(), nonce=nonce_bytes)
        print("e7na hena?")
        while True:
            msg = input("My Message: ")
            msg = symm_crypt.aes_encrypt(msg)
            chatServerSocket.sendall(msg)
            data = chatServerSocket.recv(1024)
            data = symm_crypt.aes_decrypt(data)
            print(f"Message: {data!r}")
        
    else:
        aes_and_nonce, signature = chatServerSocket.recv(1024).decode().split(" ")
        
        aes_and_nonce = base64.b64decode(aes_and_nonce)
        aes_and_nonce_HASHED = SHA256.new(aes_and_nonce)
        signature = base64.b64decode(signature)

        friend_public_key =RSA.import_key(base64.b64decode(friend_public_key.strip()))

        try:
            pkcs1_15.new(friend_public_key).verify(aes_and_nonce_HASHED, signature)
            print("SUIIII")
        except:
            print("LAAAAA")
        
        aes_and_nonce = rsa_decrypt(MY_PRIVATE_KEY, aes_and_nonce)
        
        AES_KEY, NONCE = aes_and_nonce.decode().split(" ")
        
        nonce_bytes = struct.pack('<Q', int(NONCE))

        my_symm_crypt = AESCryptography(key=AES_KEY.encode(), nonce=nonce_bytes)

        while True:
            
            data = chatServerSocket.recv(1024)
            data  = my_symm_crypt.aes_decrypt(data)
            print(f"Message: {data!r}")
            
            msg = input("My Message: ")
            msg = my_symm_crypt.aes_encrypt(msg)
            chatServerSocket.sendall(msg)
            
    

