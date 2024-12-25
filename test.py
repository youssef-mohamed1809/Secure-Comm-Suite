import base64
from Crypto.PublicKey import RSA
import json
from Cryptography import sha_256_hash, rsa_encrypt, rsa_decrypt
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


f = open("authority_private.txt", "r")
# AUTHORITY_PRIVATE_KEY = RSA.f.read()
AUTHORITY_PRIVATE_KEY = RSA.import_key(base64.b64decode(f.read().strip()))
f.close()

f = open("authority_public.txt", "r")
KEY_MANAGER_PUBLIC_KEY = RSA.import_key(base64.b64decode(f.read().strip()))
f.close()


friendPublicKey = None
with open('users.json', 'r') as file:
    data = json.load(file)
    users = data['users']
    for user in users:
        if user['username'] == "joe":
            friendPublicKey = user['public_key']
            

# friendPublicKey_HASHED_AND_ENCRYPTED = rsa_encrypt(AUTHORITY_PRIVATE_KEY, sha_256_hash(friendPublicKey).encode())

# friendPublicKeyOBJ = RSA.import_key(base64.b64decode(friendPublicKey.strip()))

# print(type(friendPublicKey))
hashhh = SHA256.new(friendPublicKey.encode())
signature = pkcs1_15.new(AUTHORITY_PRIVATE_KEY).sign(hashhh)


EL_MESSAGE_MN_EL_SERVER = friendPublicKey + " " + base64.b64encode(signature).decode("UTF-8")



#################################
    


friend_public_key, friend_public_key_hashedAndEncrypted = EL_MESSAGE_MN_EL_SERVER.split(" ")

friend_public_key_HASHED = SHA256.new(friend_public_key.encode())
print(type(friend_public_key_HASHED))
print(friend_public_key_HASHED)
friend_public_key_hashedAndEncrypted = base64.b64decode(friend_public_key_hashedAndEncrypted)
# print(type(friend_public_key_hashedAndEncrypted))
# friend_public_key_DECRYPTED = rsa_decrypt(KEY_MANAGER_PUBLIC_KEY, friend_public_key_hashedAndEncrypted)
# print(type(friend_public_key_DECRYPTED))
# print(friend_public_key_DECRYPTED)

pkcs1_15.new(KEY_MANAGER_PUBLIC_KEY).verify(friend_public_key_HASHED, friend_public_key_hashedAndEncrypted)
# if friend_public_key_HASHED == friend_public_key_DECRYPTED.decode():
#     print("SUIII")
