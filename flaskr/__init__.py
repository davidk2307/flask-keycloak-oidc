import os
import json
from flask import Flask,session,url_for,redirect
from flask_oidc import OpenIDConnect

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    app.config.update(
        TESTING=True,
        SECRET_KEY='flask-keycloak-oidc',
        OIDC_SCOPES=["openid", "email", "profile"],
        # client_secrets.json file is put in the instance folder (not in repo) and needs to have the following strucutre:
        # {
        #     "web": {
        #         "client_id": "habook",
        #         "client_secret": "",
        #         "auth_uri": "",
        #         "token_uri": "",
        #         "userinfo_uri": "",
        #         "issuer": "",
        #         "redirect_uris": [""]
        #     }
        # }
        OIDC_CLIENT_SECRETS=os.path.join(app.instance_path, 'client_secrets.json'),
    )

    oidc = OpenIDConnect(app)
    
    @app.route('/')
    def index():
        if oidc.user_loggedin:
            return 'Welcome %s' % session["oidc_auth_profile"].get('email')
        else:
            return 'Not logged in'

    @app.route('/login')
    @oidc.require_login
    def login():
        return 'Welcome %s' % session["oidc_auth_profile"].get('email')

    return app

def create_app_oauth(test_config=None):

    from authlib.integrations.flask_client import OAuth
    from dotenv import load_dotenv
    import base64
    import re
    import hashlib

    load_dotenv()

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    app.config.update(
        SECRET_KEY='flask-keycloak-oidc',
        KEYCLOAK_CLIENT_ID=os.environ["KEYCLOAK_CLIENT_ID"],
        KEYCLOAK_CODE_CHALLENGE_METHOD="S256",
        KEYCLOAK_CLIENT_SECRET=os.environ["KEYCLOAK_CLIENT_SECRET"],
    )

    oauth = OAuth(app)
    oauth.register(
        name='keycloak',
        server_metadata_url=os.environ["KEYCLOAK_SERVER_METADATA_URL"],
        client_kwargs={
            'scope': 'openid'
        }
    )

    @app.route('/')
    def homepage():
        user = session.get("user")
        if user:
            return "Hello, %s!" % user['name']
        else:
            return "Not logged in"


    @app.route('/login')
    def login():
        redirect_uri = url_for('authorize', _external=True)
        return oauth.keycloak.authorize_redirect(redirect_uri, code_challenge=code_challenge, code_challenge_method="S256")

    @app.route('/authorize')
    def authorize():
        token = oauth.keycloak.authorize_access_token(code_verifier=code_verifier)
        session['user'] = token['userinfo']
        return redirect('/')

    return app
    

if __name__ == '__main__':
    app = create_app_oauth()
    app.run()