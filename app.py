from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    province = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.String(20), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if 'user' in session:
        return render_template('home.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email, password=password).first()

        if user:
            session['user'] = {'name': user.name, 'email': user.email}
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials, please try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        city = request.form['city']
        province = request.form['province']
        country = request.form['country']
        postal_code = request.form['postal_code']
        email = request.form['email']
        password = request.form['password']
        dob = request.form['dob']

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please try a different one.')
            return redirect(url_for('signup'))

        # Create new user instance
        new_user = User(name=name, address=address, city=city, province=province, country=country, postal_code=postal_code, email=email, password=password, dob=dob)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    # Your existing code for password recovery
    pass

@app.route('/verify_code', methods=['POST'])
def verify_code():
    # Your existing code for verifying code
    pass

@app.route('/set_new_password', methods=['POST'])
def set_new_password():
    # Your existing code for setting new password
    pass

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
