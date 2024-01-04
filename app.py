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
import dropbox
import requests
import time
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('POSTGRE_USER')}:{os.getenv('POSTGRE_PASSWORD')}@{os.getenv('POSTGRE_HOST')}/{os.getenv('POSTGRE_DATABASE')}"
db = SQLAlchemy(app)

app.secret_key = os.getenv("FLASK_SECRET")
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("YOUTUBE_CLIENT_ID"),
    client_secret=os.getenv("YOUTUBE_CLIENT_SECRET"),
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
    try:
        token = google.authorize_access_token()
        token = json.dumps(token)
        token_query = text("UPDATE public.users SET youtube = pgp_sym_encrypt(:token, :key) WHERE email = :email")
        db.session.execute(token_query, {"token": token, "key": os.getenv('SECRET_KEY'), "email": session.get('email')})
        db.session.commit()
    except:
        flash("Something Went Wrong!! Please Try Again")
    return redirect(url_for("dashboard"))

@app.route("/instagram-login")
@login_required
def instagramLogin():
    return redirect(f"https://www.facebook.com/v18.0/dialog/oauth?client_id={os.getenv('INSTAGRAM_CLIENT_ID')}&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fsignin-instagram&scope=ads_management,business_management,instagram_basic,instagram_content_publish,pages_read_engagement")

@app.route("/signin-instagram")
@login_required
def instagramCallback():
    code = request.args.get('code')
    if code:
        token_exchange_url = f"https://graph.facebook.com/v18.0/oauth/access_token?client_id={os.getenv('INSTAGRAM_CLIENT_ID')}&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fsignin-instagram&client_secret={os.getenv('INSTAGRAM_CLIENT_SECRET')}&code={code}"
        token = requests.get(token_exchange_url).json()
        token = json.dumps(token)
        token_query = text("UPDATE public.users SET instagram = pgp_sym_encrypt(:token, :key) WHERE email = :email")
        db.session.execute(token_query, {"token": token, "key": os.getenv('SECRET_KEY'), "email": session.get('email')})
        db.session.commit()
    else:
        flash('Something Went Wrong!! Please Try Again')
    return redirect(url_for('dashboard'))

@app.route('/upload-youtube', methods=['POST'])
@login_required
def upload_youtube():
    token_query = text('SELECT pgp_sym_decrypt(youtube, :key) FROM public.users WHERE email = :email')
    token = db.session.execute(token_query, {'key': os.getenv('SECRET_KEY'), 'email': session.get('email')}).scalar()
    token = json.loads(token)
    if datetime.now() >= datetime.fromtimestamp(token.get('expires_at')):
        params = {
        'grant_type': 'refresh_token',
        'client_id': os.getenv('YOUTUBE_CLIENT_ID'),
        'client_secret': os.getenv('YOUTUBE_CLIENT_SECRET'),
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
        client_id=os.getenv('YOUTUBE_CLIENT_ID'),
        client_secret=os.getenv('YOUTUBE_CLIENT_SECRET')
    )
    # file = request.files['file']
    # response = upload_video_to_youtube(credentials, file)
    if response == 'success':
        return jsonify({'message':'Video Uploaded on YouTube'})
    else:
        return jsonify({'message':'Something Went Wrong!! Video is not uploaded on YouTube'})

@app.route('/upload-instagram', methods=['POST'])
@login_required
def upload_instagram():
    token_query = text('SELECT pgp_sym_decrypt(instagram, :key) FROM public.users WHERE email = :email')
    token = db.session.execute(token_query, {'key': os.getenv('SECRET_KEY'), 'email': session.get('email')}).scalar()
    token = json.loads(token)
    url = f"https://graph.facebook.com/v18.0/me/accounts?access_token={token.get('access_token')}"
    fb_page_id = requests.get(url).json()['data'][0]['id']
    url = f"https://graph.facebook.com/v18.0/{fb_page_id}?fields=instagram_business_account&access_token={token.get('access_token')}"
    ig_id = requests.get(url).json()['instagram_business_account']['id']
    video_link = 'https://www.pexels.com/video/man-on-a-pier-at-a-beautiful-river-5512609/'
    url = f"https://graph.facebook.com/v18.0/{ig_id}/media?media_type=REELS&video_url={video_link}&caption=Testing..."
    print(requests.post(url).json())
    # dbx = dropbox.Dropbox(os.getenv('DROPBOX_ACCESS_TOKEN'))
    # file = request.files['file']
    # dbx.files_upload(file.read(), f'/{file.filename}.mp4')
    # video_link_metadata = dbx.sharing_create_shared_link_with_settings(f'/{file.filename}.mp4')
    # video_link = video_link_metadata.url
    # video_link = 'https://www.pexels.com/video/man-on-a-pier-at-a-beautiful-river-5512609/'
    # url = f"https://graph.facebook.com/v18.0/{ig_id}/media?media_type=REELS&video_url={video_link}&caption=Testing..."
    # payload = {
    #     'access_token': token.get('access_token'),
    #     'media_type': 'VIDEO',
    #     'video_url': video_link,
    #     'caption': 'Testing...'
    # }
    # creation_id = requests.post(url).json()
    # if 'error' in creation_id:
        # dbx.files_delete_v2(f'/{file.filename}.mp4')
    #     print("Error creating container:", creation_id['error'])
    #     return redirect(url_for('dashboard'))
    # else:
    #     creation_id = creation_id.get('id')
    #     print(creation_id)
    #     publish_url = f"https://graph.facebook.com/v18.0/{ig_id}/media_publish"
    #     publish_payload = {
    #         'access_token': token.get('access_token'),
    #         'creation_id': creation_id
    #     }
        # requests.post(publish_url, data=publish_payload)
        # dbx.files_delete_v2(f'/{file.filename}.mp4')
    return jsonify({'message':'Done'})

@app.route("/logout")
@login_required
def logout():
    session.pop("email", None)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)