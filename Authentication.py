import json
from Cryptography import sha_256_hash
from KeyManager import generate_rsa_keys

def login(username, password):
    with open('users.json', 'r') as file:
        data = json.load(file)
        users = data['users']
        for user in users:
            if user['username'] == username and user['password'] == password:
                print("Enta sa7")
                return True
        return False
                
                
def create_account(username, password, public_key):
    with open('users.json', 'r') as file:
        data = json.load(file)
        users = data['users']
        
    with open('users.json', 'w') as file:
        users.append({"username": username, "password": password, "public_key": public_key})
        data['users'] = users
        json.dump(data, file)
        
    
    
    return True
    
    
# create_account("seif", "123")