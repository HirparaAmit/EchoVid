import os
from flask import Flask, url_for, session, redirect, request, render_template
from authlib.integrations.flask_client import OAuth
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google.oauth2.credentials import Credentials
from io import BytesIO

app = Flask(__name__)

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
    client_kwargs={'scope': 'https://www.googleapis.com/auth/youtube.upload'},
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
    return response

@app.route("/")
def home():
    return render_template("index.html", session=session.get("user"))

@app.route("/google-login")
def googleLogin():
    redirect_uri = url_for('googleCallback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/signin-google")
def googleCallback():
    token = google.authorize_access_token()
    session['user'] = token
    return redirect(url_for("home"))

@app.route('/upload', methods=['POST'])
def upload_video():
    file = request.files['file']
    token = session.get('user')
    credentials = Credentials(
        token=token.get('access_token'),
        refresh_token=token.get('refresh_token'),
        token_uri='https://oauth2.googleapis.com/token',
        client_id=os.getenv('OAUTH2_CLIENT_ID'),
        client_secret=os.getenv('OAUTH2_CLIENT_SECRET')
    )
    response = upload_video_to_youtube(credentials, file)
    return "Done"

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)