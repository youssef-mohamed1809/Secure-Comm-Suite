import socket
from Crypto.PublicKey import RSA
from _thread import *
from Authentication import login, create_account, usernameUnique
from KeyManager import get_public_key
from Cryptography import sha_256_hash, create_signature
import base64

HOST = "127.0.0.1"
PORT = 65432

AUTHORITY_PRIVATE_KEY = None

conns = []

class Client:
    def __init__(self, username, connection, public_key):
        self.username = username
        self.connection = connection
        self.public_key = public_key


def client_handler(conn):
    username = ""
    auth_choice = conn.recv(1024).decode()
    
    if auth_choice == "1":
        # LOGIN
        res = False
        while not res:
            auth_data = conn.recv(1024).decode().split(':')
            username = auth_data[0]
            res = login(auth_data[0], auth_data[1]) 
            if not res:
                conn.sendall(b"0")    
        conn.sendall(b"1")
    else:
        # CREATE AN ACCOUNT
        res = False
        while not res:
            auth_data = conn.recv(1024).decode().split(':')
            res = None
            if usernameUnique(auth_data[0]):
                res = True
            else:
                res = False
            if not res:
                conn.sendall(b"0")    
        conn.sendall(b"1")
        public_key = conn.recv(1024).decode()
        create_account(auth_data[0], auth_data[1], public_key)
    
    
    friend_username = conn.recv(1024).decode()
    friendPublicKey = get_public_key(friend_username)      
    
    friendPublicKey_HASHED = sha_256_hash(friendPublicKey)
    signature = create_signature(AUTHORITY_PRIVATE_KEY, friendPublicKey_HASHED)
    
    
    
    msg = friendPublicKey + " " + base64.b64encode(signature).decode("UTF-8")
    conn.send(msg.encode())
    
    data = conn.recv(1024)
    for i in range(len(conns)):
        if conns[i] != conn:
            conns[i].sendall(data)

if __name__ == "__main__":
    
    f = open("authority_private.txt", "r")
    AUTHORITY_PRIVATE_KEY = RSA.import_key(base64.b64decode(f.read().strip()))
    f.close()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            conns.append(conn)
            start_new_thread(client_handler, (conn,))
        
