# Functions File for the Double hashing project

import hashlib
import json
import os
import random

################################################################
# File Management
################################################################
# Each User data will follow this structure:
# {
#     "username": {
#         "kdf_salt": "kdf_salt_value",
#         "final_salt": "final_salt_value",
#         "hash": "hashed_password",
#         "credit": 0"
#     }
# }

# Initializing the json file
def init_data():
    if not os.path.exists('users.json'):
        data = {}
        save_file(data)

# Loading User Data from json file
def load_file():
    with open('users.json') as json_file:
        data = json.load(json_file)
        return data
    
# Saving User Data to json file
def save_file(data):
    with open('users.json', 'w') as outfile:
        json.dump(data, outfile)

# Force save
def force_save_file():
    data = load_file()
    save_file(data)

# Function to check if username already exists
def username_check(username):
    data = load_file()
    if username in data:
        return True
    else:
        return False

################################################################
# Main Hashing Functions
################################################################

################################################################
# RANDOM GENERATOR
def random_gen():
    '''Generates a random value of length 10'''
    salt = ""
    for i in range(0, 10):
        salt = salt + chr(random.randint(33, 126))
    return salt

################################################################
# PBKDF
def pbkdf(pwd,salt,c,dkLen):
    # pwd is the password as a string
    # salt is the salt as a string
    # c is the number of iterations as an integer
    # dkLen is the length of the derived key as an integer
    # returns the derived key as a string of hex characters

    # convert pwd and salt to byte arrays
    pwd = pwd.encode()
    salt = salt.encode()
    P = pwd + salt

    # initialize derived key to empty string
    DK = b''
    for i in range(1,c+1):
        U = hashlib.sha256(P).digest()
        P = U
        DK = DK + U
    return DK.hex()[:dkLen]

################################################################
# Salting
def salting(pwd,salt):
    return pwd + salt

################################################################
# Pepper
def pepper(pwd,pepper):
    return pwd + pepper

################################################################
# Double Hashing
def double_hash(pwd):
    # pwd is the password as a string
    # returns the double hashed password as a string of hex characters
    return hashlib.sha256(hashlib.sha512(pwd.encode()).digest()).hexdigest()

################################################################
# Pepper Checking
def pepper_check():
    # If file exists, return the pepper value from the file
    # If file does not exist, generate a random pepper value and save it to the file and also return the value
    if os.path.exists('pepper.txt'):
        with open('pepper.txt', 'r') as f:
            pepper = f.read()
            return pepper
    else:
        pepper = random_gen()
        with open('pepper.txt', 'w') as f:
            f.write(pepper)
            return pepper
        
################################################################
# hash function
def hash(user, pwd, kdf_salt, main_salt):
    main_pepper = pepper_check()

    kdf = pbkdf(pwd, kdf_salt, 100, 64)
    salted = salting(kdf, main_salt)
    peppered = pepper(salted, main_pepper)

    double_hashed = double_hash(peppered)

    return user, kdf_salt, main_salt, double_hashed

################################################################
# verify function
def verify(user,pwd):
    data = load_file()

    kdf_salt = data[user]["kdf_salt"]
    main_salt = data[user]["main_salt"]

    double_hashed = hash(user, pwd, kdf_salt, main_salt)[3]

    return double_hashed == data[user]["hash"]

############################################################
# Functions for the GUI
############################################################

# Function to get the credit value of a user
def get_credit(username):
    data = load_file()
    return data[username]["credit"]

# Function to update the credit value of a user
def set_credit(username, password, credit):
    if username_check(username):
        if verify(username, password):
            data = load_file()
            data[username]["credit"] = credit
            save_file(data)
            return True
        else:
            return False
    else:
        return False

# Function to log in a user
def log_in(username, password):
    if username_check(username):
        if verify(username, password):
            return True
        else:
            return False
    else:
        return False
    
# Function to sign up a user
def sign_up(username, password):
    if username_check(username):
        return False
    else:
        data = load_file()
        kdf_salt = random_gen()
        main_salt = random_gen()
        user, kdf_salt, main_salt, double_hashed = hash(username, password, kdf_salt, main_salt)
        data[user] = {
            "kdf_salt": kdf_salt,
            "main_salt": main_salt,
            "hash": double_hashed,
            "credit": 0
                    }
        save_file(data)
        return True