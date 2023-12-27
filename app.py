from flask import Flask, url_for, session, redirect, request, render_template
import json
import os
import requests
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET")
oauth = OAuth(app)
oauth.register(
    "myApp",
    client_id=os.getenv("OAUTH2_CLIENT_ID"),
    client_secret=os.getenv("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "https://www.googleapis.com/auth/youtube.upload",
    },
    server_metadata_url=f'{os.getenv("OAUTH2_META_URL")}',
)

@app.route("/")
def home():
    return render_template("home.html", session=session.get("user"), pretty=json.dumps(session.get("user"), indent=4))

@app.route("/google-login")
def googleLogin():
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))

@app.route("/signin-google")
def googleCallback():
    token = oauth.myApp.authorize_access_token()
    session["user"] = token
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)