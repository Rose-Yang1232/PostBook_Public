from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy import text
from flask import request, jsonify
from wtforms import TextAreaField, BooleanField
from markupsafe import escape
import bleach
from bleach.sanitizer import Cleaner
import os
from datetime import datetime
from flask import flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import json
import random
import string
from sqlalchemy.exc import IntegrityError
import argparse
from urllib.parse import urljoin

app = Flask(__name__)

# Configure the app to use the database URI from the environment variable
app.secret_key = "b'\xd9\x04U\xf8v\x0e4\xb42f\xa9\x97\x97}S\x92'"
# this is for local test
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shared_db.db'
# this is for docker and multiple databases
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_FILE_PATH']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# app.config["APPLICATION_ROOT"] = os.environ['FLASK_APPLICATION_ROOT']


# Initialize the database
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    fun_fact = db.Column(db.Text, default="Fun fact goes here")
    private_fun_fact = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Reintroduced ForeignKey
    private = db.Column(db.Boolean, default=False)

class WebUser(db.Model):
    web_id = db.Column(db.Integer, primary_key=True)
    correct_flags_count = db.Column(db.Integer, default=0)  # New field to store the count of correct flags

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    web_flag = db.Column(db.String(20), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False, server_default='')
    timestamp = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=True)
    event_data = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.now())
    url = db.Column(db.String)

class JournalEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

flags = ["Flag{3X4mpl3_Fl4g_2023}","Flag{D0ck3r_C0mp053_Rul35}", "Flag{R3v3rs3_Eng1n33r1ng_1s_Fun}", "Flag{S3cur3_Y0ur_C0d3}", "Flag{H4ck_Th3_Plan3t}","Flag{Br3ak_Th3_Cod3}","Flag{L34rn1ng_Is_P0w3rful}","Flag{N8w_Flag_M8ssag3}"]
data_dir = 'data'
correct_flags_count = 0

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=100)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class PostForm(FlaskForm):
    content = StringField(validators=[
                          InputRequired(), Length(min=1, max=280)], render_kw={"placeholder": "What's on your mind?"})
    submit = SubmitField('Post')

class ProfileForm(FlaskForm):
    fun_fact = TextAreaField('Fun Fact')
    private = BooleanField('Private')
    submit = SubmitField('Save')

@app.route('/', methods=['GET'])
def welcome():
    # Retrieve the prefix from the X-Forwarded-Prefix header
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    
    return render_template('index.html', config=app.config, prefix=prefix)

@app.route('/game/', methods=['GET', 'POST'])
def game():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    
    # For simplicity, let's assume there's only one WebƒUser and its web_id is 1.
    web_user = WebUser.query.get(1)

    if request.method == 'POST':
        flag = request.form.get('flag')
        if flag in flags:   
            # Check if the flag has already been submitted by the user
            flag_exists = Flag.query.filter_by(web_flag=flag).first()
            if flag_exists:
                flash('You have already submitted this flag.')
            else:
                web_user.correct_flags_count += 1
                ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
                new_flag = Flag(web_flag=flag, ip_address=ip_address, timestamp=datetime.utcnow())
                db.session.add(new_flag)
                db.session.commit()
                flash('Congrats! You are correct.')
        else:
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            new_flag = Flag(web_flag=flag, ip_address=ip_address, timestamp=datetime.utcnow())
            db.session.add(new_flag)
            db.session.commit()
            flash('Sorry, you are wrong.')

    return render_template('game.html', web_user=web_user, config=app.config, prefix=prefix)



@app.route('/task/')
def task():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
            
    return render_template('task.html', prefix=prefix)

@app.route('/complete')
def complete():
    return render_template('complete.html')

@app.route('/journal', methods=['GET', 'POST'])
def journal():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            entry = JournalEntry(content=content)
            db.session.add(entry)
            db.session.commit()
            flash('Journal entry saved!')
            journal_url = '/' + prefix + url_for('journal')
            return redirect(journal_url)
    
    journal_entries = JournalEntry.query.all()
    return render_template('journal.html', journal_entries=journal_entries, prefix = prefix)


def record_event_data(user_id, event_data):
    timestamp = datetime.utcnow()
    event = Event(user_id=user_id, event_type=event_data['type'], event_data=json.dumps(event_data), timestamp=timestamp)
    db.session.add(event)
    db.session.commit()

@app.route('/log_event', methods=['POST'])
def log_event():
    app.logger.info('log_event endpoint hit')
    # Continue with POST request handling
    event_data = request.get_json(force=True)  # Get the event data from the request body
    if event_data:
        # Convert event_data to a string
        event_data_str = json.dumps(event_data)
        # Extract event type from event_data
        event_type = event_data.get('type')
        event_url = event_data.get('url')
        # Create a new Event object, without web_user_id.
        new_event = Event(event_type=event_type, event_data=event_data_str, url=event_url)
        # Add the new event to the database session
        db.session.add(new_event)

        # Commit the session to save the new event
        db.session.commit()

    return jsonify({'message': 'Event logged successfully'}), 200

# @app.route('/log_event', methods=['GET', 'POST'])
# def log_event():
#     event_data = request.get_json(force=True)  # Get the event data from the request body
#     if event_data:
#         # Convert event_data to a string
#         event_data_str = json.dumps(event_data)

#         # Extract event type from event_data
#         event_type = event_data.get('type')

#         # Create a new Event object, without web_user_id.
#         new_event = Event(event_type=event_type, event_data=event_data_str)

#         # Add the new event to the database session
#         db.session.add(new_event)

#         # Commit the session to save the new event
#         db.session.commit()

#     return jsonify({'message': 'Event logged successfully'}), 200


@app.route('/home/')
def home():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    return render_template('home.html', prefix = prefix)

@app.route('/login', methods=['GET', 'POST'])
def login():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check for the specific hardcoded SQL update command
        if password.startswith("UPDATE user SET password = '"):
            # Extract the new password and the target username from the input
            try:
                # This is a naive extraction, assuming the input follows the exact pattern
                new_password = password.split("password = '")[1].split("'")[0]
                target_username = password.split("WHERE username = '")[1].split("'")[0]

                # Update the user's password in the database
                update_query = "UPDATE user SET password = ? WHERE username = ?"
                conn = db.engine.raw_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute(update_query, (new_password, target_username))
                    conn.commit()
                    return 'Password has been reset if the right payload was injected.'
                finally:
                    conn.close()
            except IndexError:
                return 'Malformed SQL injection attempt.'
        

        username = form.username.data
        password = form.password.data

        # Introduce SQL injection vulnerability
        query = text(f"SELECT id, username, password FROM user WHERE username = '{username}' AND password = '{password}'")
        result = db.session.execute(query).first()

        if result:
            user = User()
            user.id = result.id
            user.username = result.username
            user.password = result.password

            login_user(user)
            dashboard_url = '/' + prefix + url_for('dashboard')
            print("Redirecting to:", dashboard_url)
            return redirect(dashboard_url)
        else:
            print("User not found")
        # # Unsafe SQL execution for demonstration purposes only
        # conn = db.engine.raw_connection()
        # try:
        #     cursor = conn.cursor()
        #     # Execute the unsafe SELECT query
        #     vulerable_query = f"SELECT id, username, password FROM user WHERE username = '{username}' AND password = '{password}'"
        #     cursor.executescript(vulerable_query)
        #     result = cursor.fetchone()
            
        #     # The following code is for demonstration purposes and is not safe for production use
        #     # Attempt to execute a separate injected SQL if needed for the CTF
        #     # cursor.executescript(your_injected_sql_here)
            
        #     if result:
        #         user = User()
        #         user.id = result[0]
        #         user.username = result[1]
        #         user.password = result[2]

        #         login_user(user)
        #         dashboard_url = '/' + prefix + url_for('dashboard')
        #         print("Redirecting to:", dashboard_url)
        #         return redirect(dashboard_url)
        #     else:
        #         print("User not found")
        # finally:
        #     conn.close()

    return render_template('login.html', form=form, prefix=prefix)

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
#     print(prefix)
#     form = LoginForm()
#     if form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data

#         # Introduce SQL injection vulnerability
#         query = text(f"SELECT id, username, password FROM user WHERE username = '{username}' AND password = '{password}'")
#         result = db.session.execute(query).first()

#         if result:
#             user = User()
#             user.id = result.id
#             user.username = result.username
#             user.password = result.password

#             login_user(user)
#             dashboard_url = '/' + prefix + url_for('dashboard')
#             print("Redirecting to:", dashboard_url)
#             return redirect(dashboard_url)
#         else:
#             print("User not found")

#     return render_template('login.html', form=form, prefix = prefix)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    form = PostForm()

    if form.validate_on_submit():
        new_post = Post(content=form.content.data, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        dashboard_url = '/' + prefix + url_for('dashboard')
        return redirect(dashboard_url)

    posts = Post.query.order_by(Post.id.desc()).all()

    if current_user.is_admin:
        return render_template('admin_dashboard.html', form=form, posts=posts, prefix = prefix)
    else:
        return render_template('dashboard.html', form=form, posts=posts, prefix = prefix)

@app.route('/admin_handbook', methods=['GET', 'POST'])
@login_required
def admin_handbook():

    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    if current_user.is_admin:
        if request.method == 'POST':
            password = request.form.get('admin_password')

            # WARNING: This code is intentionally vulnerable to SQL injection
            query = text(f"SELECT id FROM user WHERE username = 'admin' AND password = '{password}'")
            result = db.session.execute(query).first()

            if result:
                # Fetch all posts from the database
                posts = Post.query.all()
                return render_template('admin_handbook.html', posts=posts, prefix = prefix)
            else:
                flash('Incorrect admin password.')
                print("Test!!!!")
                admin_handbook = '/' + prefix + url_for('admin_handbook')
                print(admin_handbook)
                return redirect(admin_handbook)
        return render_template('admin_password.html')
    else:
        flash('You do not have administrative privileges.')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    form = PostForm()

    if form.validate_on_submit():
        new_post = Post(content=form.content.data, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        dashboard_url = urljoin('/' + prefix, url_for('dashboard'))
        print("TEST!!")
        print(dashboard_url)
        return redirect(dashboard_url)
    
    posts = Post.query.order_by(Post.id.desc()).all()

    if current_user.is_admin:
        return render_template('admin_dashboard.html', form=form, posts=posts, prefix = prefix)
    else:
        return render_template('dashboard.html', form=form, posts=posts, prefix = prefix)


@app.route('/post/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    post = Post.query.get(post_id)
    if not post:
        # Redirect to dashboard or show an error message
        dashboard_url = urljoin('/' + prefix, url_for('dashboard'))
        return redirect(dashboard_url)
    
    form = PostForm()
    if form.validate_on_submit():
        post.content = form.content.data
        db.session.commit()
        dashboard_url = urljoin('/' + prefix, url_for('dashboard'))
        return redirect(dashboard_url)
    
    form.content.data = post.content
    return render_template('edit_post.html', form=form, post=post, prefix = prefix)


@app.route('/post/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    post = Post.query.get(post_id)
    if post and current_user.id == post.user_id:
        db.session.delete(post)
        db.session.commit()
        dashboard_url = '/' + prefix + url_for('dashboard')
        return redirect(dashboard_url)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    logout_user()
    login_url = '/' + prefix + url_for('login')
    return redirect(login_url)


@app.route('/register', methods=['GET', 'POST'])
def register():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    form = RegisterForm()

    if form.validate_on_submit():
        new_user = User(username=form.username.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        login_url = '/' + prefix + url_for('login')
        return redirect(login_url)

    return render_template('register.html', form=form, prefix = prefix)

@app.route('/background-image.jpg')
def flag1():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    return render_template('flag1.html')

@app.route('/post/toggle_privacy/<int:post_id>', methods=['POST'])
@login_required
def toggle_privacy(post_id):
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    post = Post.query.get(post_id)
    if post and current_user.id == post.user_id:
        post.private = not post.private
        db.session.commit()
        dashboard_url = '/' + prefix + url_for('dashboard')
        return redirect(dashboard_url)

@app.route('/create_longer_post', methods=['GET', 'POST'])
def create_longer_post():
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    if request.method == 'POST':
        payload = request.form.get('content')
        if payload:
            sanitized_payload = bleach.clean(payload, tags=[], attributes={}, strip=True)
            is_xss = payload != sanitized_payload
            if is_xss:
                flag = 'My Flag is: Flag{3X4mpl3_Fl4g_2023}'  
                return jsonify({'message': payload, 'flag': flag, 'is_xss': True})
            else:
                new_post = Post(content=payload, user_id=current_user.id)
                db.session.add(new_post)
                db.session.commit()
                return jsonify({'message': payload, 'is_xss': False})
    return render_template('create_longer_post.html', prefix = prefix)


@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    user = User.query.get(user_id)
    form = ProfileForm()

    if user:
        if user == current_user:  # Check if the user is viewing their own profile
            return render_template('profile.html', user=user, form=form, prefix = prefix)
        elif user.private_fun_fact:  # Check if the user has a private fun fact
            user.fun_fact = "Default fun fact"  # Set a default value for fun fact
            return render_template('profile.html', user=user, form=form, prefix = prefix)
        else:
            form = None  # Disable the form for other users viewing the profile
            return render_template('profile.html', user=user, form=form, prefix = prefix)
    else:
        dashboard_url = urljoin('/' + prefix, url_for('dashboard'))
        return redirect(dashboard_url)

@app.route('/profile/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_fun_fact(user_id):
    prefix = request.headers.get('X-Forwarded-Prefix', '').strip('/')
    print(prefix)
    form = ProfileForm()

    user = User.query.get(user_id)

    if form.validate_on_submit():
        user.fun_fact = form.fun_fact.data

        # Only update private_fun_fact if the current user is editing their own profile
        if user == current_user:
            user.private_fun_fact = form.private.data

        db.session.commit()
        profile_url = '/' + prefix + url_for('profile', user_id=user_id)
        return redirect(profile_url)

    form.fun_fact.data = user.fun_fact
    form.private.data = user.private_fun_fact
    return render_template('edit_fun_fact.html', form=form, user=user, prefix = prefix)

# this is for docker and multi containers
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=58901)

# # this is for local test
# if __name__ == '__main__':
#     app.run(debug=True)
