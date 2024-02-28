from flask import Flask, render_template

dummy_check = "dummy"
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/signin')
def signin():
    # this page will have a form that recieves username and password and checks it against the database "dummy"
    # we will retrieve the username and password from the form and check it against the database here in this function
    # if the username and password are correct, we will redirect to the account page
    # if the username and password are incorrect, we will redirect to the signin pagw with an error message
    return render_template('signin.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/<name>/account')
def account(name):
    return render_template('account.html', name=name)

@app.route('/about')
def about():
    return "About page"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')