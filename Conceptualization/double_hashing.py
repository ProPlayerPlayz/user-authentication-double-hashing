import hashlib
import json

# File to store user sign-up data
user_data_file = "user_data.json"

# Simulated user database (stores username and double-hashed password)
user_database = {}

def double_hash(password):
    hashed_password_1 = hashlib.sha256(password.encode()).hexdigest()
    double_hashed_password = hashlib.sha256(hashed_password_1.encode()).hexdigest()
    return double_hashed_password

def save_user_data():
    with open(user_data_file, "w") as file:
        json.dump(user_database, file)

def load_user_data():
    try:
        with open(user_data_file, "r") as file:
            user_database.update(json.load(file))
    except FileNotFoundError:
        pass

def sign_up():
    username = input("Enter a username: ").replace(" ", "_")
    password = input("Enter a password: ")
    
    if username in user_database:
        print("Username already taken.")
    else:
        double_hashed_password = double_hash(password)
        user_database[username] = double_hashed_password
        save_user_data()
        print("Sign-up successful!")

def log_in():
    username = input("Enter your username: ").replace(" ", "_")
    password = input("Enter your password: ")
    
    if username in user_database:
        stored_double_hashed_password = user_database[username]
        double_hashed_password_attempt = double_hash(password)
        
        if double_hashed_password_attempt == stored_double_hashed_password:
            print("Authentication successful!")
        else:
            print("Authentication failed.")
    else:
        print("Username not found.")

def main():
    load_user_data()
    
    while True:
        print("\n1. Sign up")
        print("2. Log in")
        print("3. Quit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            sign_up()
        elif choice == "2":
            log_in()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

    save_user_data()

if __name__ == "__main__":
    main()
