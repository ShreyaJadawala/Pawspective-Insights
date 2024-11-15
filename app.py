from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import numpy as np
import tensorflow as tf
from PIL import Image
from tensorflow.keras.utils import load_img, img_to_array
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import bcrypt
from random import randint
from flask_cors import CORS
from flask_mail import Mail, Message
from azure.communication.email import EmailClient
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file


app = Flask(__name__)
CORS(app)  # Enable CORS for all routes


# Fetch secret key and Azure connection string from environment variables
app.secret_key = os.getenv('SECRET_KEY')

# Constants for file upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

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
b_model = tf.keras.models.load_model('models/Breed_model.keras')

# Load the mood analysis model
mood_model = tf.keras.models.load_model('models/Mood_model.keras')

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///project.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure Azure connection string from environment
app.config['AZURE_CONNECTION_STRING'] = os.getenv('AZURE_CONNECTION_STRING')


mail=Mail(app)

# Define User model with is_admin attribute
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
    is_admin = db.Column(db.Boolean, default=False)  # New field for admin role
    date_created = db.Column(db.DateTime, default=datetime.now())

# Initialize admin if none exists
def initialize_admin():
    admin_email = "admin@example.com"
    admin_password = "admin_password"

    # Check if an admin user already exists
    if not User.query.filter_by(is_admin=True).first():
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create the admin user
        admin_user = User(
            name="Admin User",
            address="Admin Address",
            city="City",
            province="Province",
            country="Country",
            postal_code="12345",
            email=admin_email,
            password=hashed_password,
            dob="2000-01-01",
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created with email:", admin_email)
    else:
        print("Admin user already exists.")



class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)  # Correct type for date
    time = db.Column(db.Time, nullable=False)  # Correct type for time
    clinic = db.Column(db.String(200), nullable=False)
    pet_id = db.Column(db.Integer, db.ForeignKey('pet.id'), nullable=False)
    pet = db.relationship('Pet', backref=db.backref('appointments', lazy=True))

# Define Pet model
class Pet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    breed = db.Column(db.String(100))
    age = db.Column(db.Integer)
    weight = db.Column(db.String(20))  
    sex = db.Column(db.String(10))  
    image = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result_type = db.Column(db.String(50))  
    result_text = db.Column(db.String(200))  # Analysis result
    image = db.Column(db.String(200))  # Path to the analyzed image
    timestamp = db.Column(db.DateTime, default=datetime.now)  # Changed to datetime.now
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    feedback_text = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('feedbacks', lazy=True, cascade="all, delete"))




with app.app_context():
    db.create_all()  # Ensures tables are created
    initialize_admin()  # Ensures an admin exists

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

# Helper function for breed prediction
def predict_breed(image_path):
    img = load_img(image_path, target_size=(224, 224))  # Resize image for the model
    img_array = img_to_array(img)
    img_array = tf.expand_dims(img_array, 0)  # Create a batch of size 1
    
    # Make predictions
    predictions = b_model.predict(img_array)
    score = predictions[0]
    
    predicted_class = breed_class_names[np.argmax(score)]
    confidence = 100 * np.max(score)
    
    return predicted_class, confidence

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if 'user' in session:
        # flash('Redirecting to home','primary')
        print(session)
        return render_template('home.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user' in session and session['user'].get('is_admin'):
        return render_template('admin_dashboard.html')  # Admin dashboard page
    flash("Admin access required.", "danger")
    return redirect(url_for('login'))


@app.route('/admin_view_users')
def admin_view_users():
    # Fetch all users from the database

    users = User.query.filter_by(is_admin=False).all()  # Display only non-admin users
    return render_template('admin_users.html', users=users)


# Route to edit a specific user
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Update user details from form inputs
        user.name = request.form['name']
        user.address = request.form['address']
        user.city = request.form['city']
        user.province = request.form['province']
        user.country = request.form['country']
        user.postal_code = request.form['postal_code']
        user.email = request.form['email']
        user.dob = request.form['dob']
        user.is_admin = 'is_admin' in request.form  # Checkbox for admin role

        db.session.commit()
        flash('User details updated successfully.', 'success')
        return redirect(url_for('admin_view_users'))

    return render_template('admin_edit_user.html', user=user)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Delete all feedback entries for the user
    Feedback.query.filter_by(user_id=user.id).delete()

    # Delete all history entries and their images for the user
    history_entries = History.query.filter_by(user_id=user.id).all()
    for entry in history_entries:
        # Construct the full file path for the image
        image_path = os.path.join('static', entry.image)
        
        # Check if the file exists, then delete it
        if os.path.exists(image_path):
            os.remove(image_path)
    
    # Now delete history entries from the database
    History.query.filter_by(user_id=user.id).delete()

    # Delete all pets and their images for the user
    pets = Pet.query.filter_by(user_id=user.id).all()
    for pet in pets:
        # Delete pet-related appointments
        Appointment.query.filter_by(pet_id=pet.id).delete()

        # Construct the full file path for the pet's image
        pet_image_path = os.path.join('static', 'uploads', f"user_{user.id}", pet.image)
        
        # Check if the file exists, then delete it
        if os.path.exists(pet_image_path):
            os.remove(pet_image_path)

    # Delete all pets from the database
    Pet.query.filter_by(user_id=user.id).delete()

    # Finally, delete the user
    db.session.delete(user)
    db.session.commit()

    flash('User and all associated data deleted successfully.', 'success')
    return redirect(url_for('admin_view_users'))

@app.route('/admin/user_details/<int:user_id>')
def admin_view_user_details(user_id):
    # Fetch user details
    user = User.query.get_or_404(user_id)

    # Fetch the user's prediction history, pets, and appointments
    history_entries = History.query.filter_by(user_id=user_id).order_by(History.timestamp.desc()).all()
    pets = Pet.query.filter_by(user_id=user_id).all()
    
    # Fetch appointments for each pet
    pet_appointments = {pet.id: Appointment.query.filter_by(pet_id=pet.id).all() for pet in pets}

    return render_template('admin_user_details.html', user=user, history_entries=history_entries, pets=pets, pet_appointments=pet_appointments)

@app.route('/submit_feedback', methods=['GET', 'POST'])
def submit_feedback():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        feedback_text = request.form['feedback_text']
        rating = int(request.form['rating'])  # Assuming rating is from a select dropdown
        
        user_id = session['user']['id']
        new_feedback = Feedback(user_id=user_id, feedback_text=feedback_text, rating=rating)
        db.session.add(new_feedback)
        db.session.commit()
        
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('home'))
    
    return render_template('submit_feedback.html')

@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    if 'user' not in session or not session['user']['is_admin']:
        flash("Admin access required.", "danger")
        return redirect(url_for('login'))

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
        is_admin = 'is_admin' in request.form  # Checkbox for admin role

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please try a different one.', 'warning')
            return redirect(url_for('admin_add_user'))

        # Hash the password before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create new user instance
        new_user = User(
            name=name,
            address=address,
            city=city,
            province=province,
            country=country,
            postal_code=postal_code,
            email=email,
            password=hashed_password,
            dob=dob,
            is_admin=is_admin
        )
        db.session.add(new_user)
        db.session.commit()

        flash('New user added successfully!', 'success')
        return redirect(url_for('admin_view_users'))

    return render_template('admin_add_user.html')

@app.route('/admin/feedback')
def admin_feedback():
    if 'user' not in session or not session['user']['is_admin']:
        flash("Admin access required.", "danger")
        return redirect(url_for('login'))
    
    # Fetch all feedback entries excluding those from admin users
    feedbacks = (db.session.query(Feedback)
                 .join(User)
                 .filter(User.is_admin == False)
                 .order_by(Feedback.timestamp.desc())
                 .all())

    # Calculate average rating, excluding admin feedback
    avg_rating = (db.session.query(db.func.avg(Feedback.rating))
                  .join(User)
                  .filter(User.is_admin == False)
                  .scalar())
    

    return render_template('admin_feedback.html', feedbacks=feedbacks, avg_rating=avg_rating)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return redirect(url_for('home') + '#services')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/my_profile')
def my_profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user']['id'])
    return render_template('profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user']['id'])

    if request.method == 'POST':
        user.name = request.form['name']
        user.address = request.form['address']
        user.city = request.form['city']
        user.province = request.form['province']
        user.country = request.form['country']
        user.postal_code = request.form['postal_code']

        db.session.commit()
        session['user'] = {'name': user.name, 'email': user.email, 'id': user.id}
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('my_profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user']['id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        # Verify current password
        if bcrypt.checkpw(current_password.encode('utf-8'), user.password.encode('utf-8')):
            # Hash the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password.decode('utf-8')
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('my_profile'))
        else:
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))


    return render_template('change_password.html')

@app.route('/my_pets')
def my_pets():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get the pets for the logged-in user
    user_id = session['user']['id']
    pets = Pet.query.filter_by(user_id=user_id).all()
    
    return render_template('my_pets.html', pets=pets)


@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    history_entries = History.query.filter_by(user_id=user_id).order_by(History.timestamp.desc()).all()

    return render_template('history.html', history_entries=history_entries) 


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
        weight = request.form['weight']
        sex = request.form['sex']
        image = request.files.get('image')  # Get the uploaded file

        if image and allowed_file(image.filename):
            # Define the upload folder based on user and pet name
            image_filename = secure_filename(image.filename)
            user_folder = f"{session['user']['name']}_{name}"
            upload_folder = os.path.join('static', 'uploads', user_folder)  # Save under static/uploads/user_petname
            os.makedirs(upload_folder, exist_ok=True)  # Ensure the upload directory exists
            
            # Save the image in the user's specific folder
            filepath = os.path.join(upload_folder, image_filename)
            image.save(filepath)
            
            # Store the relative path from the 'static' folder in the database
            relative_image_path = user_folder +'/'+ image_filename
            
            user_id = session['user']['id']
            new_pet = Pet(name=name, breed=breed, age=age, weight=weight, sex=sex, image=relative_image_path, user_id=user_id)
            db.session.add(new_pet)
            db.session.commit()
            flash('New pet added successfully', 'success')

            return redirect(url_for('my_pets'))
        else:
            flash('Please upload a valid image file (png, jpg, jpeg).', 'danger')
    return render_template('add_pet.html')

@app.route('/edit_pet/<int:pet_id>', methods=['GET', 'POST'])
def edit_pet(pet_id):
    pet = Pet.query.get_or_404(pet_id)

    if request.method == 'POST':
        pet.name = request.form['name']
        pet.breed = request.form['breed']
        pet.age = request.form['age']
        pet.weight = request.form['weight']
        pet.sex = request.form['sex']

        # Handle image file
        image = request.files.get('image')  # Use .get to avoid KeyError

        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            upload_folder = os.path.join('static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, image_filename)
            image.save(filepath)
            pet.image = image_filename  # Update pet's image if a new one is uploaded

        db.session.commit()
        flash('Pet details updated successfully!', 'success')
        return redirect(url_for('customize_pets'))

    return render_template('edit_pet.html', pet=pet)

@app.route('/remove_pet/<int:pet_id>', methods=['GET', 'POST'])
def remove_pet(pet_id):
    pet = Pet.query.get_or_404(pet_id)

    if request.method == 'POST':
        # If the user confirms deletion
        if request.form.get('action') == 'confirm':
            db.session.delete(pet)
            db.session.commit()
            flash(f'{pet.name} has been removed.', 'success')
            return redirect(url_for('customize_pets'))
        # If the user cancels deletion
        return redirect(url_for('customize_pets'))

    return render_template('confirm_delete.html', pet=pet)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        # Check if user exists and verify password
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['user'] = {'id': user.id,'name':user.name, 'is_admin': user.is_admin}

            # Redirect to admin dashboard if user is admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('home'))
        
        flash('Invalid login credentials.', 'danger')
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
            flash('Email already exists. Please try a different one.','warning')
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
        
        flash('Registration successful! Please login.','success')
        return redirect(url_for('login'))
    return render_template('signup.html')


# Function to send recovery code via email
def send_recovery_code(to_email, recovery_code):
    client = EmailClient.from_connection_string(app.config['AZURE_CONNECTION_STRING'])
    message = {
        "senderAddress": "DoNotReply@a89d27b1-a2c4-42e1-922a-2d0accd7e43b.azurecomm.net",  # Replace <from_domain> with your verified domain
        "recipients": {
            "to": [{"address": to_email}]
        },
        "content": {
            "subject": "Password Recovery Code",
            "plainText": f"Your password recovery code is: {recovery_code}",
            "html": f"""
            <html>
                <body>
                    <h2>Password Recovery</h2>
                    <p>Your password recovery code is: <b>{recovery_code}</b></p>
                </body>
            </html>"""
        },
    }

    try:
        poller = client.begin_send(message)
        result = poller.result()
        # print("Recovery email sent:", result.message_id)
    # finally:
    #     print("s")
    except Exception as ex:
        print("Failed to send recovery email:", ex)

# Route to request password recovery
@app.route('/recover_password', methods=['GET', 'POST'])
def request_password_recovery():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a 6-digit recovery code
            recovery_code = randint(100000, 999999)
            session['recovery_code'] = recovery_code
            session['recover_email'] = email

            # Send recovery code email
            send_recovery_code(email, recovery_code)
            flash('A recovery code has been sent to your email.', 'info')
            return redirect(url_for('verify_code'))

        flash('Email not found. Please try again.', 'danger')

    return render_template('recover_password.html')

# Route to verify recovery code
@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        entered_code = request.form['code']

        # Check if the entered code matches the session code
        if 'recovery_code' in session and int(entered_code) == session['recovery_code']:
            flash('Code verified. You can now set your new password.', 'success')
            return redirect(url_for('new_password'))

        flash('Invalid code. Please try again.', 'danger')

    return render_template('verify_code.html')

# Route to set a new password
@app.route('/new_password', methods=['GET', 'POST'])
def new_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        email = session.get('recover_email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Hash the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password.decode('utf-8')
            db.session.commit()

            # Clear session variables
            session.pop('recovery_code', None)
            session.pop('recover_email', None)

            flash('Your password has been updated successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Something went wrong. Please try again.', 'danger')

    return render_template('new_password.html')



@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.','success')
    return redirect(url_for('login'))

@app.route('/mood_analyzer', methods=['GET', 'POST'])
def mood_analyzer():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['image']
        if file and allowed_file(file.filename):
            # Define the upload folder specific to the user
            user_folder = os.path.join('static', 'uploads', f"user_{session['user']['id']}")
            os.makedirs(user_folder, exist_ok=True)  # Create the folder if it doesn't exist

            # Save the image to the user's folder
            image_filename = secure_filename(file.filename)
            filepath = os.path.join(user_folder, image_filename)
            file.save(filepath)

            # Run prediction
            mood, confidence = predict_mood(filepath)

            # Save result to history with user ID and path relative to static folder
            user_id = session['user']['id']
            relative_filepath = 'uploads/'+ f"user_{user_id}/"+ image_filename  # Relative path for the image
            history_entry = History(
                result_type='mood',
                result_text=f"Mood: {mood} ({confidence:.2f}%)",
                image=relative_filepath,  # Relative path
                user_id=user_id
            )
            db.session.add(history_entry)
            db.session.commit()

            # Pass the relative filepath to mood_result
            return redirect(url_for('mood_result', filepath=relative_filepath, mood=mood, confidence=confidence))
    return render_template('mood_analyzer.html')


@app.route('/mood_result')
def mood_result():
    mood = request.args.get('mood')
    confidence = request.args.get('confidence')
    filepath = request.args.get('filepath')  # Get the full relative path to the image
    
    return render_template('mood_result.html', filepath=filepath, mood=mood, confidence=confidence)
@app.route('/breed_analyzer', methods=['GET', 'POST'])
def breed_analyzer():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['image']
        if file and allowed_file(file.filename):
            # Define the upload folder specific to the user
            user_folder = os.path.join('static', 'uploads', f"user_{session['user']['id']}")
            os.makedirs(user_folder, exist_ok=True)  # Create the folder if it doesn't exist

            # Save the image to the user's folder
            image_filename = secure_filename(file.filename)
            filepath = os.path.join(user_folder, image_filename)
            file.save(filepath)

            # Run prediction
            breed, confidence = predict_breed(filepath)

            # Save result to history with user ID and relative path to the static folder
            user_id = session['user']['id']
            relative_filepath = 'uploads/'+ f"user_{user_id}/"+ image_filename  # Relative path for the image
            history_entry = History(
                result_type='breed',
                result_text=f"Breed: {breed} ({confidence:.2f}%)",
                image=relative_filepath,  # Use relative path
                user_id=user_id
            )
            db.session.add(history_entry)
            db.session.commit()

            return render_template('breed_result.html', image_path=relative_filepath, breed=breed, confidence=confidence)
    return render_template('breed_analyzer.html')


# Prevent unauthorized profile access
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user' not in session or session['user']['id'] != user_id:
        flash('Unauthorized access!','danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.name = request.form['name']
        user.address = request.form['address']
        user.city = request.form['city']
        user.province = request.form['province']
        user.country = request.form['country']
        user.postal_code = request.form['postal_code']
        db.session.commit()

        flash('Profile updated successfully!','success')
        return redirect(url_for('home'))

    return render_template('edit_profile.html', user=user)

# Bulk upload route for testing system overload
@app.route('/bulk_upload', methods=['GET', 'POST'])
def bulk_upload():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        files = request.files.getlist('images')

        if len(files) > 50:
            flash('Too many files uploaded at once. Please try again with fewer images.','danger')
            return redirect(url_for('bulk_upload'))

        for file in files:
            if file and allowed_file(file.filename):
                upload_folder = os.path.join('static', 'uploads')
                os.makedirs(upload_folder, exist_ok=True)
                filepath = os.path.join(upload_folder, secure_filename(file.filename))
                file.save(filepath)

        flash(f'Successfully uploaded {len(files)} images.','success')
        return redirect(url_for('bulk_upload'))

    return render_template('bulk_upload.html')

@app.route('/pet_details/<int:pet_id>', methods=['GET'])
def pet_details(pet_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    pet = Pet.query.get_or_404(pet_id)
    appointments = Appointment.query.filter_by(pet_id=pet.id).all()

    return render_template('pet_details.html', pet=pet, appointments=appointments)


# Function to send appointment confirmation email
def send_appointment_email(to_email, pet_name, date, time, clinic):
    client = EmailClient.from_connection_string(app.config['AZURE_CONNECTION_STRING'])
    message = {
        "senderAddress": "DoNotReply@a89d27b1-a2c4-42e1-922a-2d0accd7e43b.azurecomm.net",  # Replace <from_domain> with your verified domain
        "recipients": {
            "to": [{"address": to_email}]
        },
        "content": {
            "subject": f"Appointment Reminder for {pet_name}",
            "plainText": f"You have scheduled an appointment for {pet_name} on {date} at {time} at {clinic}.",
            "html": f"""
            <html>
                <body>
                    <h2>Appointment Reminder</h2>
                    <p>You have scheduled an appointment for <b>{pet_name}</b> on <b>{date}</b> at <b>{time}</b> at <b>{clinic}</b>.</p>
                </body>
            </html>"""
        },
    }

    try:
        poller = client.begin_send(message)
        result = poller.result()
        print("Appointment email sent:", result.message_id)
    except Exception as ex:
        print("Failed to send appointment email:", ex)

# Function to send appointment cancellation email
def send_cancellation_email(to_email, pet_name, date, time, clinic):
    client = EmailClient.from_connection_string(app.config['AZURE_CONNECTION_STRING'])
    message = {
        "senderAddress": "DoNotReply@a89d27b1-a2c4-42e1-922a-2d0accd7e43b.azurecomm.net",  # Replace <from_domain> with your verified domain
        "recipients": {
            "to": [{"address": to_email}]
        },
        "content": {
            "subject": f"Appointment Cancellation for {pet_name}",
            "plainText": f"The appointment for {pet_name} on {date} at {time} at {clinic} has been canceled.",
            "html": f"""
            <html>
                <body>
                    <h2>Appointment Cancellation</h2>
                    <p>The appointment for <b>{pet_name}</b> on <b>{date}</b> at <b>{time}</b> at <b>{clinic}</b> has been canceled.</p>
                </body>
            </html>"""
        },
    }

    try:
        poller = client.begin_send(message)
        result = poller.result()
        print("Cancellation email sent:", result.message_id)
    except Exception as ex:
        print("Failed to send cancellation email:", ex)


# add_appointment route
@app.route('/add_appointment/<int:pet_id>', methods=['GET', 'POST'])
def add_appointment(pet_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    pet = Pet.query.get_or_404(pet_id)

    if request.method == 'POST':
        date_str = request.form['date']
        time_str = request.form['time']
        clinic = request.form['clinic']

        try:
            appointment_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            appointment_time = datetime.strptime(time_str, '%H:%M').time()
        except ValueError:
            flash('Invalid date or time format. Please try again.', 'danger')
            return redirect(url_for('add_appointment', pet_id=pet.id))

        existing_appointment = Appointment.query.filter_by(pet_id=pet.id, date=appointment_date, time=appointment_time).first()
        if existing_appointment:
            flash('This time slot is already booked. Please select a different time.', 'warning')
            return redirect(url_for('add_appointment', pet_id=pet.id))

        new_appointment = Appointment(date=appointment_date, time=appointment_time, clinic=clinic, pet_id=pet.id)
        db.session.add(new_appointment)
        db.session.commit()

        user = User.query.get(pet.user_id)
        send_appointment_email(user.email, pet.name, appointment_date, appointment_time, clinic)
        flash('Appointment added and email sent!', 'success')
        return redirect(url_for('pet_details', pet_id=pet.id))

    return render_template('add_appointment.html', pet=pet)

# Route to delete appointment
@app.route('/remove_appointment/<int:appointment_id>', methods=['POST'])
def remove_appointment(appointment_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    appointment = Appointment.query.get_or_404(appointment_id)
    pet = Pet.query.get(appointment.pet_id)
    user = User.query.get(pet.user_id)

    db.session.delete(appointment)
    db.session.commit()

    send_cancellation_email(user.email, pet.name, appointment.date, appointment.time, appointment.clinic)
    flash('Appointment canceled and email sent!', 'success')
    return redirect(url_for('pet_details', pet_id=pet.id))



if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0",port=8000)
