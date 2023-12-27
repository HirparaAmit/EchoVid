from flask import Flask, url_for, session, redirect, request, render_template
import json
import requests
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
appConf = {
    "OAUTH2_CLIENT_ID": "394024938730-cde4t7t88rb9eqr6cci4eiflls8rse1s.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "0b0e2adc-82ae-4bc2-8b8f-95fb6da9139b",
    "FLASK_PORT": 5000
}
app.secret_key = appConf.get("FLASK_SECRET")
oauth = OAuth(app)
oauth.register(
    "myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "https://www.googleapis.com/auth/youtube.upload",
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',
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
    app.run(port=appConf.get("FLASK_PORT"), debug=True)