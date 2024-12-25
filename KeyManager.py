from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import json
import base64
from Cryptography import sha_256_hash

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    private_key_b64 = base64.b64encode(private_key).decode('utf-8')
    public_key_b64 = base64.b64encode(public_key).decode('utf-8')
    return private_key_b64, public_key_b64
def generate_aes_key_and_nonce():
    key = get_random_bytes(16)
    nonce = get_random_bytes(16)
    return key, nonce
def get_public_key(username):
    with open('users.json', 'r') as file:
        data = json.load(file)
        entries = data['users']
        for entry in entries:
            if entry['username'] == username:
                key = entry['public']
                # key = base64.b64decode(key)
                # key = RSA.import_key(key)
                return key
def get_private_key(username):
    print("ahlan")
    file = open('users.json', 'r')
    data = json.load(file)
    entries = data['users']
    # print(entries)
    for entry in entries:
        if entry['username'] == username:
            # print("galy el key1")
            print(entry['username'])
            key = entry['private']
            # key = base64.b64decode(key)
            # key = RSA.import_key(key)
            return key


if __name__ == "__main__":
    pass
    priv, public = generate_rsa_keys()
    
    # print(priv)
    # print("--------------------")
    # print(public)
    
    f = open("authority_private.txt", "w")
    f.write(priv)
    f.close()
    
    
    f = open("authority_public.txt", "w")
    f.write(public)
    f.close()
    # file = open('users.json', 'r')
    # data = json.load(file)
    # entries = data['users']
    
    
    # # with open(f'key_manager/users.json', 'r') as file:
    # #     data = json.load(file)
    # #     users = data['users']
    
    # # with open(f'key_manager/users.json', 'w') as file:
    # #     users.append({"username": "joe", "password": sha_256_hash("hello"), "public_key": public})
    # #     data['users'] = users
    # #     json.dump(data, file)


## seif password: 12345
## joe password: hello