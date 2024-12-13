from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import numpy as np
import tensorflow as tf
from PIL import Image
from tensorflow.keras.utils import load_img, img_to_array
from werkzeug.utils import secure_filename
import bcrypt
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Load the mood class names
mood_class_names = ['Angry', 'Happy', 'Relaxed', 'Sad']

# Load breed names from the text file
def load_breed_names(file_path):
    with open(file_path, 'r') as f:
        breeds = [line.strip() for line in f.readlines()]
    return breeds

# Load the class names from the text file
breed_class_names = load_breed_names('formatted_breed_class_list.txt')

# Breed Identification model
# Load the model once at the start
b_model = tf.keras.models.load_model('models/Breed_model.keras')

# Load the mood analysis model
mood_model = tf.keras.models.load_model('models/Mood_model.keras')

# Helper function to predict mood
def predict_mood(image_path):
    img = load_img(image_path, target_size=(224, 224))
    img_array = img_to_array(img)
    img_array = tf.expand_dims(img_array, 0)  # Create a batch for the model

    predictions = mood_model.predict(img_array)
    score = tf.nn.softmax(predictions[0])
    mood = mood_class_names[np.argmax(score)]
    confidence = 100 * np.max(score)

    return mood, confidence

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

# Define Pet model
class Pet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    breed = db.Column(db.String(100))
    age = db.Column(db.Integer)
    image = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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

# Updated login route with bcrypt password verification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Fetch user from database
        user = User.query.filter_by(email=email).first()

        # Check if user exists and password matches the hash
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['user'] = {'name': user.name, 'email': user.email, 'id': user.id}
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials, please try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

# Updated signup route with bcrypt password hashing
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

        # Hash the password before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create new user instance
        new_user = User(
            name=name,
            address=address,
            city=city,
            province=province,
            country=country,
            postal_code=postal_code,
            email=email,
            password=hashed_password.decode('utf-8'),  # Store as string in DB
            dob=dob
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    return render_template('recover_password.html')

@app.route('/verify_code', methods=['POST'])
def verify_code():
    return render_template('verify_code.html')

@app.route('/set_new_password', methods=['POST'])
def set_new_password():
    return render_template('new_password.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/mood_analyzer', methods=['GET', 'POST'])
def mood_analyzer():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['image']
        if file and file.filename != '':
            upload_folder = os.path.join('static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, file.filename)
            file.save(filepath)

            # Perform mood analysis
            mood, confidence = predict_mood(filepath)
            
            return redirect(url_for('mood_result', filename=file.filename, mood=mood, confidence=confidence))
        else:
            flash('Please select a file to upload.')
            return redirect(url_for('mood_analyzer'))

    return render_template('mood_analyzer.html')

@app.route('/mood_result/<filename>')
def mood_result(filename):
    mood = request.args.get('mood')
    confidence = request.args.get('confidence')
    
    return render_template('mood_result.html', filename=filename, mood=mood, confidence=confidence)

@app.route('/breed_analyzer', methods=['GET', 'POST'])
def breed_analyzer():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['image']
        if file and file.filename != '':
            upload_folder = os.path.join('static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, file.filename)
            file.save(filepath)
            
            # Process the uploaded image for prediction
            img = load_img(filepath, target_size=(224, 224))  # Resize image for the model
            img_array = img_to_array(img)
            img_array = tf.expand_dims(img_array, 0)  # Create a batch of size 1
            
            # Make predictions
            predictions = b_model.predict(img_array)
            score = predictions[0]
            
            predicted_class = breed_class_names[np.argmax(score)]
            confidence = 100 * np.max(score)
            
            # Pass the result to a result page
            return render_template('breed_result.html', filename=file.filename, breed=predicted_class, confidence=confidence)
        
        else:
            flash('Please select a file to upload.')
            return redirect(url_for('breed_analyzer'))

    return render_template('breed_analyzer.html')

@app.route('/breed_result/<filename>')
def breed_result(filename):
    breed = request.args.get('breed')
    confidence = request.args.get('confidence')
    return render_template('breed_result.html', filename=filename, breed=breed, confidence=confidence)

@app.route('/my_pets')
def my_pets():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get the pets for the logged-in user
    user_id = session['user']['id']
    pets = Pet.query.filter_by(user_id=user_id).all()
    
    return render_template('my_pets.html', pets=pets)

@app.route('/customize_pets')
def customize_pets():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get the pets for the logged-in user
    user_id = session['user']['id']
    pets = Pet.query.filter_by(user_id=user_id).all()
    
    return render_template('customize_pets.html', pets=pets)

@app.route('/add_pet', methods=['GET', 'POST'])
def add_pet():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        breed = request.form['breed']
        age = request.form['age']
        image = request.files['image']

        # Save the uploaded image
        if image and image.filename != '':
            image_filename = image.filename
            upload_folder = os.path.join('static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, image_filename)
            image.save(filepath)
        else:
            image_filename = None

        # Add pet to the database
        user_id = session['user']['id']
        new_pet = Pet(name=name, breed=breed, age=age, image=image_filename, user_id=user_id)
        db.session.add(new_pet)
        db.session.commit()

        return redirect(url_for('my_pets'))
    
    return render_template('add_pet.html')

if __name__ == '__main__':
    app.run(debug=True,port=8080)
