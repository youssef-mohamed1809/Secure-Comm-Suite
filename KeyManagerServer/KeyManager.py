from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import json
import base64
from Cryptography import sha_256_hash

def get_public_key(username):
    with open('users.json', 'r') as file:
        data = json.load(file)
        entries = data['users']
        for entry in entries:
            if entry['username'] == username:
                key = entry['public_key']
                return key


def get_private_key(username):
    file = open('users.json', 'r')
    data = json.load(file)
    entries = data['users']
    for entry in entries:
        if entry['username'] == username:
            print(entry['username'])
            key = entry['private']
            return key

if __name__ == "__main__":
    pass



## seif password: 12345
## joe password: hello