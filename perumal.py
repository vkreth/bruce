from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vamsi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flask_lab7.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    firstname = StringField('Firstname', validators=[DataRequired()])
    lastname = StringField('Lastname', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class SigninForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['user_name']
        firstname = request.form['first_name']
        lastname = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not all([username, firstname, lastname, email, password, confirm_password]):
            return redirect(url_for('signup'))

        if password != confirm_password:
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return redirect(url_for('signup'))
        
        if not is_valid_password(password):
            return redirect(url_for('signup'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, firstname=firstname, lastname=lastname, 
                        email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('thankyou'))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('signup'))

    return render_template('signup.html')
    if request.method == 'POST':
        username = request.form['user_name']
        firstname = request.form['first_name']
        lastname = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not all([username, firstname, lastname, email, password, confirm_password]):
            return redirect(url_for('signup'))

        if password != confirm_password:
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, firstname=firstname, lastname=lastname, 
                        email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('thankyou'))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('signup'))

    return render_template('signup.html')
    if request.method == 'POST':
        user_name = request.form['user_name']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        
        new_user = User(username=user_name, firstname=first_name, lastname=last_name, email=email, password=password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('signin'))
        except Exception as e:
            db.session.rollback()
            print(f"Error: {str(e)}")
            return "An error occurred", 500

    return render_template('signup.html')

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully.')
            return redirect(url_for('secretpage'))
        else:
            flash('Invalid username or password')
    return render_template('signin.html')
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/secretpage')
@login_required
def secretpage():
    user = User.query.get(session['user_id'])
    if user is None:
        session.pop('user_id', None)
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('signin'))
    return render_template('secretpage.html', user=user)
@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html', title='Registration Successful')

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

if __name__ == '_main_':
    with app.app_context():
        db.create_all()
        app.run(debug=True)