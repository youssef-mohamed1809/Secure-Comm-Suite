import json

def login(username, password):
    with open('users.json', 'r') as file:
        data = json.load(file)
        users = data['users']
        for user in users:
            if user['username'] == username and user['password'] == password:
                print("User Autheticated")
                return True
        return False
                
                
def create_account(username, password, public_key):
    if not usernameUnique(username):
        return False
    
    with open('users.json', 'r') as file:
        data = json.load(file)
        users = data['users']
        
    with open('users.json', 'w') as file:
        users.append({"username": username, "password": password, "public_key": public_key})
        data['users'] = users
        json.dump(data, file)
    
    return True

def usernameUnique(username):
    with open('users.json', 'r') as file:
        data = json.load(file)
        users = data['users']
    for user in users:
        if(user['username'] == username):
            return False
    return True
    
    
