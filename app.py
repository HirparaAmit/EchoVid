import os
from flask import Flask, url_for, session, redirect, request, render_template, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google.oauth2.credentials import Credentials
from io import BytesIO
from functools import wraps
import json
import requests
import random
import time
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('POSTGRE_USER')}:{os.getenv('POSTGRE_PASSWORD')}@{os.getenv('POSTGRE_HOST')}/{os.getenv('POSTGRE_DATABASE')}"
db = SQLAlchemy(app)

app.secret_key = os.getenv("FLASK_SECRET")
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("OAUTH2_CLIENT_ID"),
    client_secret=os.getenv("OAUTH2_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'https://www.googleapis.com/auth/youtube.upload'},
)

def upload_video_to_youtube(credentials, file):
    youtube = build('youtube', 'v3', credentials=credentials)
    body = {
        'snippet': {
            'title': 'Test',
            'description': 'Test',
            'tags': 'Comedy, Funny, lol',
            'categoryId': 22
        },
        'status': {
            'privacyStatus': 'public'
        }
    }
    media = MediaIoBaseUpload(BytesIO(file.read()), mimetype='video/*', resumable=True)
    response = youtube.videos().insert(part='snippet,status', body=body, media_body=media)
    response = response.execute()
    if 'id' in response:
        return "success"
    else:
        return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
@login_required
def dashboard():
    data_query = text('SELECT (youtube IS NULL), (instagram IS NULL) FROM public.users WHERE email = :email')
    youtube, instagram = db.session.execute(data_query, {"email": session.get('email')}).fetchone()
    platforms = {
        'youtube': youtube,
        'instagram': instagram
    }
    connected = [key for key, value in platforms.items() if not value]
    pending = [key for key, value in platforms.items() if value]
    return render_template("home.html", connected=connected, pending=pending)

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form. get('password')
        email_check = text("SELECT COUNT(*) FROM public.users WHERE email = :email")
        email_check = db.session.execute(email_check, {'email': email}).scalar()
        if email_check > 0:
            flash("Email already in use!")
            return redirect(url_for('signup'))
        else:
            password = generate_password_hash(password)
            sql_query = text("INSERT INTO public.users (email, password) VALUES (:email, :password)")
            db.session.execute(sql_query, {"email": email, "password": password})
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        email_check = text("SELECT COUNT(*) FROM public.users WHERE email = :email")
        email_check = db.session.execute(email_check, {'email': email}).scalar()
        if email_check:
            password_check = text("SELECT password FROM public.users WHERE email = :email")
            password_check = db.session.execute(password_check, {'email': email}).scalar()
            if password_check and check_password_hash(password_check, password):
                session['email'] = email
                return redirect(url_for("dashboard"))
            else:
                flash("Wrong credentials!")
                return redirect(url_for('login'))
        else:
            flash("Wrong credentials!")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route("/youtube-login")
@login_required
def youtubeLogin():
    redirect_uri = url_for('googleCallback', _external=True)
    return google.authorize_redirect(redirect_uri, access_type='offline')

@app.route("/signin-google")
@login_required
def googleCallback():
    token = google.authorize_access_token()
    token = json.dumps(token)
    token_query = text("UPDATE public.users SET youtube = pgp_sym_encrypt(:token, :key) WHERE email = :email")
    db.session.execute(token_query, {"token": token, "key": os.getenv('SECRET_KEY'), "email": session.get('email')})
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/instagram-login")
@login_required
def instagramLogin():
    return "Instagram"

@app.route('/upload-youtube', methods=['POST'])
@login_required
def upload_youtube():
    file = request.files['file']
    token_query = text('SELECT pgp_sym_decrypt(youtube, :key) FROM public.users WHERE email = :email')
    token = db.session.execute(token_query, {'key': os.getenv('SECRET_KEY'), 'email': session.get('email')}).scalar()
    token = json.loads(token)
    if datetime.now() >= datetime.fromtimestamp(token.get('expires_at')):
        params = {
        'grant_type': 'refresh_token',
        'client_id': os.getenv('OAUTH2_CLIENT_ID'),
        'client_secret': os.getenv('OAUTH2_CLIENT_SECRET'),
        'refresh_token': token.get('refresh_token')
        }
        response = requests.post('https://oauth2.googleapis.com/token', data=params)
        if response.status_code == 200:
            token = response.json()
            token['refresh_token'] = params['refresh_token']
            token['expires_at'] = int(time.time() + token.get('expires_in'))
            token_query = text("UPDATE public.users SET youtube = pgp_sym_encrypt(:token, :key) WHERE email = :email")
            db.session.execute(token_query, {"token": json.dumps(token), "key": os.getenv('SECRET_KEY'), "email": session.get('email')})
            db.session.commit()
        else:
            token_query = text("UPDATE public.users SET youtube = NULL WHERE email = :email")
            db.session.execute(token_query, {"email": session.get('email')})
            db.session.commit()
            flash('You need to reconnect the YouTube with EchoVid')
            return redirect(url_for('dashboard'))
    credentials = Credentials(
        token=token.get('access_token'),
        refresh_token=token.get('refresh_token'),
        token_uri='https://oauth2.googleapis.com/token',
        client_id=os.getenv('OAUTH2_CLIENT_ID'),
        client_secret=os.getenv('OAUTH2_CLIENT_SECRET')
    )
    # response = upload_video_to_youtube(credentials, file)
    if response == 'success':
        return jsonify({'status':'success', 'message':'Video Uploaded on YouTube'})
    else:
        return jsonify({'status':'error', 'message':'Error Uploading Video on YouTube'})

@app.route("/logout")
@login_required
def logout():
    session.pop("email", None)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)