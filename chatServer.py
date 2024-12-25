import socket
from _thread import *

HOST = "127.0.0.1"
CHAT_SERVER_PORT = 65433
numOfConnections = 0
AES_KEY = None
NONCE = None

conns = []

def client_handler(myconn):
    global AES_KEY
    global NONCE
    global conns
    global numOfConnections
    myconn.send(str(numOfConnections).encode())
    numOfConnections += 1
    if numOfConnections == 1:
        print("Seif beyes2al lw e7na hena")
        AES_KEY, NONCE = myconn.recv(1024).decode().split(" ")
        while True:
            data = myconn.recv(1024)
            for conn in conns:
                if conn != myconn:
                    conn.send(data)
    else:
        msg = AES_KEY + " " + str(NONCE)
        myconn.send(msg.encode())
        
        while True:
            data = myconn.recv(1024)
            for conn in conns:
                if conn != myconn:
                    conn.send(data)
    

        
    



if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, CHAT_SERVER_PORT))
            s.listen()
            while True:
                conn, addr = s.accept()
                conns.append(conn)
                start_new_thread(client_handler, (conn,))