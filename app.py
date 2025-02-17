from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from forms import LoginForm, RegisterForm


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pet_adoption.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from models import User
from forms import LoginForm, RegisterForm

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    with app.app_context():
        db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    print(f"Request method: {request.method}")
    print(f"Form data: {request.form}")

    if form.validate_on_submit():
        print("Form validation passed!")
        user = User.query.filter_by(email=form.email.data).first()
        print(f"User found: {user}") 
        
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful')
            return redirect(url_for('index'))
        else:
            print("Invalid credentials!")
            flash('Invalid email or password')

    else:
        print("Form validation failed!")
        print(form.errors)  

    return render_template('login.html', form=form)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    print(f"Request method: {request.method}")
    print(f"Form data: {request.form}")

    if form.validate_on_submit():
        print("Form validation passed!")
        
    
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            print("User already exists!")
            flash("Email is already registered. Please log in.")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )

        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {e}")
            flash('An error occurred. Please try again.')

    else:
        print("Form validation failed!")
        print(form.errors) 

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/index')
def index():
    return render_template('index.html')