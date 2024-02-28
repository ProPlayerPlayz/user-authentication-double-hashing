# Functions File for the Double hashing project

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import os
import random

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
encryption_key = 'Batch B Group 17'*2  # Replace with your actual key (keep it secret!)
encryption_key = encryption_key.encode()  # Convert to bytes
#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

################################################################
# RANDOM GENERATOR
def random_gen(n=10):
    '''Generates a random value of length 10'''
    salt = ""
    for _ in range(0, n):
        salt = salt + chr(random.randint(33, 126))
    return salt

################################################################
# ENCRYPTION
################################################################

#---------------------------------------------------------------
# AES encryption function
def aes_encrypt(key, data):
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return iv + ciphertext
#---------------------------------------------------------------
# AES decryption function
def aes_decrypt(key, data):
    iv = data[:16] # Extract the IV from the first 16 bytes
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.decode('utf-8')
#----------------------------------------------------------------
################################################################
# File Management
################################################################

'''# Initializing the json file
def init_data():
    # create pepper file if it does not exist
    if not os.path.exists('pepper.txt'):
        with open('pepper.txt', 'w') as f:
            f.write(random_gen())
    
init_data()
'''
################################################################
# Main Hashing Functions
################################################################

################################################################
# PBKDF
def pbkdf(pwd,salt,c=255,dkLen=50):
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
'''# Pepper
def pepper(pwd,pepper):
    return pwd + pepper
'''
################################################################
# Double Hashing
def double_hash(pwd):
    # pwd is the password as a string
    # returns the double hashed password as a string of hex characters
    return hashlib.sha256(hashlib.sha512(pwd.encode()).digest()).hexdigest()

################################################################
'''# Pepper Checking
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
            return pepper'''
        
################################################################
# hash function
def hash(user, pwd, kdf_salt, main_salt):
    # Retrive the Encryption Key
    global encryption_key
    key = encryption_key

    # Hash the password
    kdf = pbkdf(pwd, kdf_salt)
    salted = salting(kdf, main_salt)
    double_hashed = double_hash(salted)

    # Encrypt the double_hashed value before returning it
    encrypted_hash = aes_encrypt(key, double_hashed)

    return user, kdf_salt, main_salt, encrypted_hash.hex()

################################################################
# verify function
def verify(pwd, kdf_salt, main_salt, encrypted_hash):
    # Retrive the Encryption Key
    global encryption_key
    key = encryption_key

    # Decrypt the hash before comparing
    decrypted_hash = aes_decrypt(key, bytes.fromhex(encrypted_hash))

    kdf = pbkdf(pwd, kdf_salt)
    salted = salting(kdf, main_salt)
    double_hashed = double_hash(salted)

    if double_hashed == decrypted_hash:
        return True
    else:
        return False

############################################################
# Functions for the Webpage
############################################################
       
# Function to sign up a user
def sign_up(username, password):
    kdf_salt = random_gen()
    main_salt = random_gen()
    user, kdf_salt, main_salt, encrypted_hash = hash(username, password, kdf_salt, main_salt)
        
    return user, kdf_salt, main_salt, encrypted_hash, 100

############################################################
# Session Transaction history stuff added by Parthvi
############################################################
transactions = []

def get_transaction_history(username):
    user_transactions = []
    for transaction in transactions:
        if transaction['username'] == username:
            user_transactions.append(transaction)
    return user_transactions

# Add a function to add transactions to the list
def add_transaction(username, date, transaction_type, amount):
    transactions.append({
        'username': username,
        'date': date,
        'type': transaction_type,
        'amount': amount
    })
############################################################