from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import random 
import string


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shared_db.db'  # Change the URI to your desired location
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_FILE_PATH']
db = SQLAlchemy(app)

class User(db.Model,UserMixin):
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
    
class JournalEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=True)
    event_data = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.now())
    url = db.Column(db.String)

def add_new_user(username, password, fun_fact, private, is_admin=False):
    new_user = User(username=username, password=password, fun_fact=fun_fact, private_fun_fact=private, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

def add_new_post(content, user_id, private):
    new_post = Post(content=content, user_id=user_id, private=private)
    db.session.add(new_post)
    db.session.commit()

# Function to initialize the WebUser with web_id 1
def initialize_web_user():
    web_user = WebUser.query.get(1)
    if not web_user:
        web_user = WebUser(web_id=1, correct_flags_count=0)
        db.session.add(web_user)
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        initialize_web_user()
        add_new_user(username="admin", password="11111111", fun_fact="I create a fun web called Postbook!", private=False, is_admin=True)
        add_new_user(username="Rose", password="222222222", fun_fact="I'm Elli's friend", private=False)
        add_new_user(username="ellieliiii", password="Mangoicecream", fun_fact="I like earal grey ice cream", private=False)
        add_new_user(username="Username", password="Password", fun_fact="I like to eat pho", private=False)
        add_new_user(username="Tester", password="333333333", fun_fact="My secret flag is: Flag{H4ck_Th3_Plan3t}", private=True)
        add_new_user(username="Doraemon", password="44444444", fun_fact="I do not have too many fun facts, but here is my secrete flag: Flag{Br3ak_Th3_Cod3}", private=True)
        add_new_user(username="Rosella", password="666666666", fun_fact="Fun fact goes here", private=False)
        add_new_user(username="id08", password="888888888", fun_fact="Fun fact goes here", private=False)
        
        add_new_post(content="Hello World!", user_id=1, private=False)
        add_new_post(content="My secret flag is: Flag{D0ck3r_C0mp053_Rul35}", user_id=1, private=True)
        add_new_post(content="I am so excited to share my story with you!", user_id=2, private=False)
        add_new_post(content="Wow!", user_id=2, private=False)
        add_new_post(content="This is my secret flag: Flag{R3v3rs3_Eng1n33r1ng_1s_Fun}", user_id=2, private=True)
        add_new_post(content="I like mango ice cream", user_id=3, private=False)
        add_new_post(content="but i like chai ice cream", user_id=3, private=False)
        add_new_post(content="actually i like earl grey ice cream", user_id=3, private=False)
        add_new_post(content="my secret flag is: Flag{S3cur3_Y0ur_C0d3}", user_id=4, private=True)
        add_new_post(content="My flag is: Flag{L34rn1ng_Is_P0w3rful}", user_id=8, private=True)
        add_new_post(content="just a test", user_id=5, private=False)
