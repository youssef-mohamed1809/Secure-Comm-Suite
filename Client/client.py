import socket
from Cryptography import sha_256_hash, rsa_decrypt, rsa_encrypt, verify_signature, create_signature ,generate_rsa_keys, generate_aes_key_and_nonce, AESCryptography
from Crypto.PublicKey import RSA
import base64
from Crypto.Hash import SHA256
import struct
import sys

HOST = "127.0.0.1"
KEY_MANAGER_PORT = 65432
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
        msg = username + ":" + sha_256_hash(password).hexdigest()
        keyManagerSocket.sendall(msg.encode())
        ack = keyManagerSocket.recv(1024).decode()
    
    if auth_choice != "1":
        private, public = generate_rsa_keys()
        f = open(f"{username}_private.txt", "w")
        f.write(private)
        f.close()
        keyManagerSocket.send(public.encode())
        
    
    
    f = open(f"{username}_private.txt", "r")
    MY_PRIVATE_KEY = RSA.import_key(base64.b64decode(f.read().strip()))
    f.close()
    
    f = open("authority_public.txt", "r")
    KEY_MANAGER_PUBLIC_KEY = RSA.import_key(base64.b64decode(f.read().strip()))
    f.close()
        

    friend_username = input("Input the username of the person you want to talk to: ")
    
    keyManagerSocket.send(friend_username.encode())
    
    friend_public_key, signature = keyManagerSocket.recv(1024).decode().split(" ")
    friend_public_key_HASHED = sha_256_hash(friend_public_key)
    signature = base64.b64decode(signature)           
    if verify_signature(KEY_MANAGER_PUBLIC_KEY, signature, friend_public_key_HASHED):
        print("Signature Verified")
    else:
        print("Signature Verification Failed")
        exit()

    keyManagerSocket.close()
    
    chatServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chatServerSocket.connect((HOST, CHAT_SERVER_PORT))
    
    numOfServerConnections = chatServerSocket.recv(1024).decode()
    if(int(numOfServerConnections) == 0):

        AES_KEY, NONCE = generate_aes_key_and_nonce()
        
        msg = AES_KEY + " " + str(NONCE)
        
        friend_public_key =RSA.import_key(base64.b64decode(friend_public_key.strip()))
        
        enc_key = rsa_encrypt(friend_public_key, msg.encode())
        aes_key_and_nonce_hashed = SHA256.new(enc_key)
        signature = create_signature(MY_PRIVATE_KEY, aes_key_and_nonce_hashed)
        
        
        msg =  base64.b64encode(enc_key).decode('utf-8') + " " + base64.b64encode(signature).decode("UTF-8")
        
        chatServerSocket.send(msg.encode())
        
        nonce_bytes = struct.pack('<Q', NONCE)
        
        symm_crypt = AESCryptography(key=AES_KEY.encode(), nonce=nonce_bytes)
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

            
        if verify_signature(friend_public_key, signature, aes_and_nonce_HASHED):
            print("Signature Verified")
        else:
            print("Signature Verification Failed")
            exit()
            
        
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
            
    

