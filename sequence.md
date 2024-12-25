Walkie Talkie chatting

1. login
2. get public key of friend
3. connect with chat server
4. first person to connect with server will generate AES key
5. server will tell the first person to generate AES key
6. first client will send to server the
   encrypted (with public key of reciever and private of sender) generated AES key
7. server will save the key until the second client joins
8. Once the second client connects to server, the server will send the AES key
9. START CHATTING

client

1. login
2. send username of friend
3. recieve public key of friend (plain text) + public key of friend hashed and encrypted with private key of auth
4. split message
5. hash the plain text recieved
6. decrypt the encrypted publuc key
