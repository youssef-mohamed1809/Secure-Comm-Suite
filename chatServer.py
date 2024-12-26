import socket
from _thread import *

HOST = "127.0.0.1"
CHAT_SERVER_PORT = 65433
numOfConnections = 0
AES_KEY_MSG = None

conns = []

def client_handler(myconn):
    global AES_KEY
    global NONCE
    global conns
    global numOfConnections
    global AES_KEY_MSG
    myconn.send(str(numOfConnections).encode())
    numOfConnections += 1
    if numOfConnections == 1:
        print("Seif beyes2al lw e7na hena")
        AES_KEY_MSG = myconn.recv(1024).decode()
        while True:
            data = myconn.recv(1024)
            for conn in conns:
                if conn != myconn:
                    conn.send(data)
    else:
        myconn.send(AES_KEY_MSG.encode())
        
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