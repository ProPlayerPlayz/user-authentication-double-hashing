# Importing the required modules
from flask import Flask, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import time as t

# Importing the DH module for password hashing functions
import DH as dh

# Create the Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = 'BatchBGroup17DoubleHashing'  # This is for CSRF protection

# Cross Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions
#  on a web application in which they're currently authenticated.

# Configure the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///banking.db'
db = SQLAlchemy(app)

# Create the database model
class User(db.Model):
    username = db.Column(db.String(50), primary_key=True)
    kdf_salt = db.Column(db.String(50), nullable=False)
    main_salt = db.Column(db.String(50), nullable=False)
    hash = db.Column(db.String(50), nullable=False)
    credit = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.kdf_salt}', '{self.main_salt}', '{self.hash}', '{self.credit}')"

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
csrf_ecryption_key = dh.random_gen(32).encode()
#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

############################################################################################################
# Main Flask routes

# Main page (redirects to the home page)
@app.route('/') # root directory
def index():
    return render_template('index.html')

# The actual home page
@app.route('/home')
def home():
    return render_template('home.html')

# The about page
@app.route('/services')
def services():
    return render_template('services.html')

############################################################################################################
# ENTIRE Login Logic

# Login page
@app.route('/sign_in', methods=['POST', 'GET'])
def sign_in():
    # Making sure the user is not already logged in
    session['auth'] = False

    # Creating a fail safe for preventing brute force attacks
    if 'signin_attempt' not in session:
        session['signin_attempt'] = 0

    # Generate a CSRF token for the login page form
    if 'csrf_token' not in session:
        session['csrf_token'] = dh.random_gen(32)

    
    # POST request logic
    if request.method == 'POST':
        # Check if the CSRF token matches
        if session['csrf_token'] != request.form['csrf_token']:
            session.clear()
            return render_template('error.html', alert='Error!',message='CSRF token mismatch. Logging out...')
        
        # Check if the user has attempted to login more than 10 times
        session['signin_attempt'] += 1
        if session['signin_attempt'] > 3:
            session.clear()
            return render_template('error.html', alert='Error',message='Too many attempts. Account has been blacklisted. Please contact your regional mangaer.')
        
        # Retrieve the username and password from the form
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if the user exists in the database and retrieve the user's password hash
        user = User.query.filter_by(username=username).first()
        # SELECT * FROM User WHERE username = username LIMIT 1;

        # SQL Query: SELECT * FROM User WHERE username = username LIMIT 1;
        if user is None:
            return render_template('sign_in.html',username="",password="",username_error="User does not exist",password_error="",csrf_token=session['csrf_token'])
        else:
            # Retrieve the user's password hash, kdf salt and main salt from the database
            encrypted_hash = user.hash
            kdf_salt = user.kdf_salt
            main_salt = user.main_salt
            # Check if the user's password hash matches the hash in the database
            if dh.verify(password, kdf_salt, main_salt, encrypted_hash):
                # Store user session data
                session['username'] = username
                session['auth'] = True
                return render_template('success.html', message='Login successful')
            else:
                return render_template('sign_in.html',username=username,password="",username_error="",password_error="Incorrect Password",csrf_token=session['csrf_token'])

    # GET request logic
    else:
        return render_template('sign_in.html',username="",password="",username_error="",password_error="",csrf_token=session['csrf_token'])
# END OF Login Logic
############################################################################################################

############################################################################################################
# ENTIRE Sign Up Logic
@app.route('/sign_up', methods=['POST', 'GET'])
def sign_up():
    # Making sure the user is not already logged in
    session['auth'] = False
    # Creating a fail safe for preventing brute force attacks
    if 'signup_attempt' not in session:
        session['signup_attempt'] = 0
    # Generate a CSRF token for the sign up page form
    if 'csrf_token' not in session:
        session['csrf_token'] = dh.random_gen(32)


    # POST request logic
    if request.method == 'POST':
        # Check if the CSRF token matches
        if session['csrf_token'] != request.form['csrf_token']:
            session.clear()
            return render_template('error.html', alert='Error',message='CSRF token mismatch. Logging out...')
        
        # Check if the user has attempted to login more than 10 times
        session['signup_attempt'] += 1
        if session['signup_attempt'] > 3:
            session.clear()
            return render_template('error.html',alert='Error', message='Too many attempts. Please try again later.')
        
        # Retrieve the username and password from the form
        username = request.form.get('new_username')
        password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if the user exists in the database and retrieve the user's password hash
        user_details = dh.sign_up(username,password)
        # returns user, kdf_salt, main_salt, double_hashed, 0
        # -------  0  ,    1    ,    2     ,     3        , 4
        # or
        # returns False

           
        # Store user session data
        # Run a query to check if the username already exists in the database
        user = User.query.filter_by(username=username).first()
        # SQL Query: SELECT * FROM User WHERE username = username LIMIT 1;            
        # Check if the username already exists in the database
        if user is not None:
            return render_template('sign_up.html',new_username="",new_password="",confirm_password="",username_error="Username taken.",password_error="",csrf_token=session['csrf_token'])
        # Check if the username and password are in a valid format
        elif len(username) < 4 or len(username) > 50:
            return render_template('sign_up.html',new_username=username,new_password="",confirm_password="",username_error="Username must be between 4 to 50 characters.",password_error="",csrf_token=session['csrf_token'])
        elif len(password) < 8 or len(password) > 50:
            return render_template('sign_up.html',new_username=username,new_password="",confirm_password="",username_error="",password_error="Password must be between 8 to 50 characters.",csrf_token=session['csrf_token'])
        elif not any(char.isdigit() for char in password):
            return render_template('sign_up.html',new_username=username,new_password="",confirm_password="",username_error="",password_error="Password must contain at least one number.",csrf_token=session['csrf_token'])
        elif password != confirm_password:
            return render_template('sign_up.html',new_username=username,new_password="",confirm_password="",username_error="",password_error="Passwords do not match.",csrf_token=session['csrf_token'])
        else:
            # Add the user to the database
            try:
                new_user = User(username=user_details[0], kdf_salt=user_details[1], main_salt=user_details[2], hash=user_details[3], credit=user_details[4])
                session['username'] = user_details[0] # Store the username in the user's session
                session['auth'] = True # Set the user's authentication status to True
                db.session.add(new_user)
                db.session.commit() # Commit the changes to the database
                return render_template('success.html') # Redirect to the success page
            except:
                session['auth'] = False
                return render_template('error.html',alert='Error', message='SQL Error. Please try again.')
            
    # GET request logic
    else:
        return render_template('sign_up.html',new_username="",new_password="",confirm_password="",username_error="",password_error="",csrf_token=session['csrf_token'])
# END OF ENTIRE Sign Up Stuff
############################################################################################################

############################################################################################################
# Contact form stuff
@app.route('/contact')
def contact_form():
    return render_template('contact.html')

@app.route('/contact_submit_form', methods=['POST'])
def contact_submit_form():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']

    # Write the responses to a text file
    with open('responses.txt', 'a') as file:
        file.write(f'Name: {name}\n')
        file.write(f'Email: {email}\n')
        file.write(f'Message: {message}\n\n')

    # Redirect to the 'home.html' page after submission
    return redirect(url_for('home'))
# End of contact form stuff
############################################################################################################


############################################################################################################
# ENTIRE Banking Stuff
@app.route('/logout', methods=['POST','GET'])
def logout():
    # Clear the user's session to log them out
    session.clear()
    return render_template('logout.html')


@app.route('/banking', methods=['POST', 'GET'])
def banking():
    try:
        # Creating a fail safe for preventing brute force attacks
        if 'auth' not in session:
            return render_template('error.html',alert='Error', message='Authentication failed')
        
        # Generate a CSRF token for the banking page
        if 'banking_csrf_token' not in session:
            session['banking_csrf_token'] = dh.random_gen()
        banking_csrf_token = session['banking_csrf_token']

        # Timeout logic for the banking page
        if 'auth_time' not in session:
            session['auth_time'] = t.time()
        auth_time = session['auth_time']
        
        ####### Change Timeout value here #######
        timeout_threshold = 60 # 1 minute
        ######################################### 

        # Retrieve user's credit and balance 
        username = session['username']
        account = User.query.filter_by(username=session['username']).first()
        credit = account.credit

        if request.method == 'POST':
            # Check if the CSRF token matches
            if session['banking_csrf_token'] != request.form['banking_csrf_token']:
                session.clear()
                return render_template('error.html', message='CSRF token mismatch. Logging out...')
            # Check if the user has timed out
            if (t.time() - session['auth_time']) > timeout_threshold + 10: # 10 seconds buffer
                session.clear()
                return render_template('error.html',alert='Timeout', message='Session timeout. Logging out...')
            
            # Retrieve the operation and amount from the form
            operation = request.form.get('operation')
            
            amount = float(request.form.get('amount'))

            # Check if the amount is valid
            if amount <= 1 or amount > 1000000:
                session.clear()
                return render_template('error.html',alert='Error', message='Invalid amount. \nYou cannot Deposit/Withdraw an amount greater than $10000\n and less than $1. Logging out...')
            
            # Check if the operation is valid
            # Deposit
            if operation == 'deposit':
                dh.add_transaction(username, datetime.now(), 'Deposit', amount)
                new_credit = credit + amount
                account.credit = new_credit
                db.session.commit()
            # Withdraw
            elif operation == 'withdraw':
                if credit >= amount:
                    dh.add_transaction(username, datetime.now(), 'Withdrawal', amount)
                    new_credit = credit - amount
                    account.credit = new_credit
                    db.session.commit()
                else:
                    session.clear()
                    return render_template('error.html',alert='Error', message='Insufficient credit. Logging out...')
            # Invalid operation
            else:
                session.clear()
                return render_template('error.html',alert='Error', message='Invalid operation. Logging out...')
        
        # Retrieve user's credit and balance
        balance = account.credit

        # Implement transaction history logic in the DH module and retrieve it here
        transactions = dh.get_transaction_history(username)

        return render_template('banking.html',banking_csrf_token = banking_csrf_token, auth_time = auth_time, username=username, credit=credit, balance=balance, transactions=transactions)
    except:
        session.clear()
        return render_template('error.html',alert='Error', message='Logging out...')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', ssl_context=('certificates/cert.pem', 'certificates/key.pem'))
