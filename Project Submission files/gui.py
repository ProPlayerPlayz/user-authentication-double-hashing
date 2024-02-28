# Making GUI for the program

import tkinter as tk
from tkinter import messagebox
import DH as dh
dh.init_data() # Creating the json file if it doesn't exist

##########################################################
# Functions for the sub windows
def update_credit_label():
    credit = dh.get_credit(username_raw.get())
    credit_label.config(text=str(credit))

def deposit_button_command():
    credit = dh.get_credit(username_raw.get())
    credit += int(common_raw.get())
    dh.set_credit(username_raw.get(),password_raw.get(), credit)
    update_credit_label()
    messagebox.showinfo("Info", "Credit Deposited. Your Balance is now " + str(credit) + ".")

def withdraw_button_command():
    credit = dh.get_credit(username_raw.get())
    if credit >= int(common_raw.get()):
        credit -= int(common_raw.get())
        dh.set_credit(username_raw.get(),password_raw.get(), credit)
        update_credit_label()
        messagebox.showinfo("Info", "Credit Withdrawn. Your Balance is now " + str(credit) + ".")
    else:
        messagebox.showinfo("Info", "Insufficient credit.")

def log_out_button_command():
    dh.force_save_data()
    messagebox.showinfo("Info", "You have been logged out.")
    subwin.destroy()

def bank_system_window():
    global subwin
    subwin = tk.Toplevel()
    subwin.title("Bank System")

    # Retrive the credit value from the json file
    credit = dh.get_credit(username_raw.get())
    username = username_raw.get()

    # Creating the widgets
    ## Title label and frame
    title_frame = tk.Frame(subwin)
    title_frame.grid(row=0, column=0, columnspan=2, pady=10)

    title_label = tk.Label(title_frame, text="Bank System", font=("Arial", 20))
    title_label.pack()

    ## Username and Credit label and frame
    username_credit_frame = tk.Frame(subwin)
    username_credit_frame.grid(row=1, column=0, columnspan=2, pady=10)

    username_label_label = tk.Label(username_credit_frame, text="Username: ", font=("Arial", 16))
    username_label_label.grid(row=0, column=0)

    username_label = tk.Label(username_credit_frame, text=username, font=("Consolas", 16))
    username_label.grid(row=0, column=1)

    credit_label_label = tk.Label(username_credit_frame, text="Credit: ", font=("Arial", 16))
    credit_label_label.grid(row=1, column=0)

    global credit_label
    credit_label = tk.Label(username_credit_frame, text=str(credit), font=("Arial", 16))
    credit_label.grid(row=1, column=1)

    ## Deposit and Withdraw buttons and Entry box 
    deposit_withdraw_frame = tk.Frame(subwin)
    deposit_withdraw_frame.grid(row=2, column=0, pady=10)

    deposit_button = tk.Button(deposit_withdraw_frame,command=deposit_button_command, text="Deposit", font=("Arial", 16))
    deposit_button.grid(row=0, column=0, padx=10)

    withdraw_button = tk.Button(deposit_withdraw_frame,command=withdraw_button_command, text="Withdraw", font=("Arial", 16))
    withdraw_button.grid(row=1, column=0, padx=10)

    global common_raw
    common_raw = tk.StringVar()
    common_entry = tk.Entry(deposit_withdraw_frame,textvariable=common_raw, font=("Arial", 16))
    common_entry.grid(row=0, column=1,rowspan=2, pady=10)

    ## Log out button
    log_out_button = tk.Button(subwin, text="Log Out",command=log_out_button_command, font=("Arial", 16))
    log_out_button.grid(row=3, column=0, columnspan=2, pady=10)

    subwin.transient(window)
    subwin.grab_set()
    window.wait_window(subwin)

def username_string_prune(username):
    return username.strip().replace(" ", "_")

##########################################################
# Functions for Button Commands
def sign_up_button_command():
    username = username_raw.get()
    username = username_string_prune(username)
    password = password_raw.get()
    if not dh.username_check(username):
        if dh.sign_up(username, password):
            messagebox.showinfo("Info", "Sign-up successful! You can login now using the Log In button.")
        else:
            messagebox.showinfo("Info", "Username already taken.")
    else:
        messagebox.showinfo("Info", "Username already taken.")

def log_in_button_command():
    username = username_raw.get()
    username = username_string_prune(username)
    password = password_raw.get()
    if dh.username_check(username):
        if dh.log_in(username, password):
            # Open a new window for the Bank System with a Deposit and withdraw buttons
            bank_system_window()
        else:
            messagebox.showinfo("Info", "Authentication failed.")
    else:
        messagebox.showinfo("Info", "Username not found. Sign up using the Sign Up button.")


##########################################################
# Creating the main window
window = tk.Tk()
window.title("Bank Login System")

# Creating the widgets
## Title label and frame
title_frame = tk.Frame(window)
title_frame.grid(row=0, column=0, columnspan=2, pady=10)

title_label = tk.Label(title_frame, text="Bank Login System", font=("Arial", 20))
title_label.pack()

## Username label and entry inside a frame
global username_raw
username_raw = tk.StringVar()

username_frame = tk.Frame(window)
username_frame.grid(row=1, column=0,columnspan=2, pady=10)

username_label = tk.Label(username_frame, text="Username: ", font=("Arial", 16))
username_label.pack(side=tk.LEFT)

username_entry = tk.Entry(username_frame, textvariable=username_raw, font=("Arial", 16))
username_entry.pack(side=tk.LEFT)

## Password label and entry inside a frame
global password_raw
password_raw = tk.StringVar()

password_frame = tk.Frame(window)
password_frame.grid(row=2, column=0,columnspan=2, pady=10)

password_label = tk.Label(password_frame, text="Password: ", font=("Arial", 16))
password_label.pack(side=tk.LEFT)

password_entry = tk.Entry(password_frame, textvariable=password_raw , font=("Arial", 16))
password_entry.pack(side=tk.LEFT)

## Sign up button
sign_up_button = tk.Button(window, text="Sign Up", command=sign_up_button_command, font=("Arial", 16))
sign_up_button.grid(row=3, column=0, pady=10)

## Log in button
log_in_button = tk.Button(window, text="Log In", command=log_in_button_command, font=("Arial", 16))
log_in_button.grid(row=3, column=1, pady=10)

# Running the main loop
window.mainloop()