from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask_login import UserMixin
import os
from pathlib import Path

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    private = db.Column(db.Boolean, default=False)  # Add the private field

flags = ["Flag{3X4mpl3_Fl4g_2023}","Flag{D0ck3r_C0mp053_Rul35}", "Flag{R3v3rs3_Eng1n33r1ng_1s_Fun}", "Flag{S3cur3_Y0ur_C0d3}", "Flag{H4ck_Th3_Plan3t}","Flag{Br3ak_Th3_Cod3}","Flag{L34rn1ng_Is_P0w3rful}","Flag{N8w_Flag_M8ssag3}"]
data_dir = 'data'

class WebUser(db.Model):
    web_id = db.Column(db.Integer, primary_key=True)
    web_found_flags = db.Column(db.Integer, default=0)
    db_filename = db.Column(db.String(50), nullable=False, unique=True)  

class Flag(db.Model):
    flag_id = db.Column(db.Integer, primary_key=True)
    web_flag = db.Column(db.String(20), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False, server_default='')
    timestamp = db.Column(db.DateTime, nullable=False, server_default=func.now())

class Event(db.Model):
    web_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_type = db.Column(db.String(50), nullable=True)  # Set this to nullable=False if required
    event_data = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=func.now())



if __name__ == "__main__":
    with app.app_context():  # Push an application context
        db.drop_all()  # Use with caution: This will drop all tables
        db.create_all()
        
        # Now add users and posts within this context
        user1 = User(username='admin', password='11111111', fun_fact='I create a fun website!', private_fun_fact= False, is_admin=True) 
        user2 = User(username='Rose', password='22222222', fun_fact='I am Ellie friend', private_fun_fact= False, is_admin=False)
        user3 = User(username='ellieliiii', password='Mangoicecream', fun_fact='I like earal grey ice cream', private_fun_fact= False, is_admin=False)
        user4 = User(username='Username', password='Password', fun_fact='I like to eat pho', private_fun_fact= False, is_admin=False)
        user5 = User(username='Tester', password='33333333', fun_fact='My secrete Flag is Flag{L34rn1ng_Is_P0w3rful}', private_fun_fact= True, is_admin=False) 
        user6 = User(username='Doraemon', password='44444444', fun_fact='I do not have too much fun fact, but here is my Flag Flag{Br3ak_Th3_Cod3}', private_fun_fact= True, is_admin=False)
        user7 = User(username='Rosella', password='66666666', fun_fact='Fun fact goes here..', private_fun_fact= False, is_admin=False)
        user8 = User(username='id08', password='88888888', fun_fact='Fun fact goes here..', private_fun_fact= False, is_admin=False)
        
        db.session.add(user1) 
        db.session.add(user2) 
        db.session.add(user3) 
        db.session.add(user4)  
        db.session.add(user5) 
        db.session.add(user6) 
        db.session.add(user7) 
        db.session.add(user8) 
        db.session.commit()  # Ensure user is committed to get an ID


        post1 = Post(content='Hello Word', user_id=user1.id, private = False) 
        post2 = Post(content='My secrete Flag is Flag{D0ck3r_C0mp053_Rul35}', user_id=user1.id, private = True)
        post3 = Post(content='I am so excited to write on this website', user_id=user2.id, private = False) 
        post4 = Post(content='Wow', user_id=user2.id, private = False) 
        post5 = Post(content='My secrete Flag is Flag{R3v3rs3_Eng1n33r1ng_1s_Fun}', user_id=user2.id, private = True) 
        post6 = Post(content='I like mango ice creame', user_id=user3.id, private = False)  
        post7 = Post(content='but I like chai ice cream more', user_id=user3.id, private = False) 
        post8 = Post(content='Actually I like earl grey tea ice cream!', user_id=user3.id, private = False)
        post9 = Post(content='My secrete Flag is Flag{S3cur3_Y0ur_C0d3}', user_id=user8.id, private = True) 
        post11 = Post(content='My secrete Flag is Flag{H4ck_Th3_Plan3t}', user_id=user8.id, private = True) 
        post10 = Post(content='Just a test ', user_id=user5.id, private = False)

        
        db.session.add(post1)
        db.session.add(post2)
        db.session.add(post3)
        db.session.add(post4)
        db.session.add(post5)
        db.session.add(post6)
        db.session.add(post7)
        db.session.add(post8)
        db.session.add(post9)
        db.session.add(post10)
        db.session.add(post11)

        db.session.commit()

        print("Database tables created and sample data added!")

