# Functions File for the Double hashing project

import hashlib
import json
import os

global salt
salt = "salty"

# Each User data will follow this structure:
# {
#     "username": {
#         "password": "hashed_password",
#         "credit": 0"
#     }
# }

# Initializing the json file
def init_data():
    if not os.path.exists('users.json'):
        data = {}
        save_data(data)

# Loading User Data from json file
def load_data():
    with open('users.json') as json_file:
        data = json.load(json_file)
        return data
    
# Saving User Data to json file
def save_data(data):
    with open('users.json', 'w') as outfile:
        json.dump(data, outfile)

# Force save
def force_save_data():
    data = load_data()
    save_data(data)

def double_hash(password):
    salt = "salty"
    password = password + salt
    hashed_password_1 = hashlib.sha256(password.encode()).hexdigest()
    double_hashed_password = hashlib.sha256(hashed_password_1.encode()).hexdigest()
    return double_hashed_password

'''# Hashing Function 1 (SHA256)
def hash1(key):
    # perform hashing after adding salt value
    key = key + str(salt)
    hash_object = hashlib.sha256(key.encode())  
    hex_dig = hash_object.hexdigest()
    return hex_dig


# Hashing Function 2 (SHA512)
def hash2(key):
    # perform hashing after adding salt value
    key = key + str(salt)
    hash_object = hashlib.sha512(key.encode())  
    hex_dig = hash_object.hexdigest()
    return hex_dig

# Double Hashing Function
def double_hash(key, i):
    key = key + str(salt)
    return (hash1(key) + i *hash2(key)) % 100'''


############################################################
# Functions for the GUI
############################################################

# Function to check if username already exists
def username_check(username):
    data = load_data()
    if username in data:
        return True
    else:
        return False

# Function to check if password is correct
def password_check(username, password):
    data = load_data()
    double_hashed_password = double_hash(password)
    if double_hashed_password == data[username]["password"]:
        return True
    else:
        return False

# Function to get the credit value of a user
def get_credit(username):
    data = load_data()
    return data[username]["credit"]

# Function to update the credit value of a user
def set_credit(username, password, credit):
    if username_check(username):
        if password_check(username, password):
            data = load_data()
            data[username]["credit"] = credit
            save_data(data)
            return True
        else:
            return False
    else:
        return False

# Function to log in a user
def log_in(username, password):
    if username_check(username):
        if password_check(username, password):
            return True
        else:
            return False
    else:
        return False
    
# Function to sign up a new user
def sign_up(username, password):
    data = load_data()
    if username_check(username):
        return False
    else:
        double_hashed_password = double_hash(password)
        data[username] = {
            "password": double_hashed_password,
            "credit": 0
        }
        save_data(data)
        return True
    
