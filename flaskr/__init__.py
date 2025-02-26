import os
import json
from flask import Flask,session,url_for,redirect,jsonify,request
from flask_oidc import OpenIDConnect
from authlib.oauth2.rfc7662 import (
    IntrospectTokenValidator as BaseIntrospectTokenValidator,
)

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
    from authlib.integrations.flask_oauth2 import ResourceProtector
    from dotenv import load_dotenv

    load_dotenv()

    def update_token(name, token, refresh_token=None, access_token=None):
        session["token"] = token

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

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
            'scope': 'openid',
            'code_challenge_method': 'S256'
        },
        update_token=update_token
    )

    require_oauth = ResourceProtector()

    class IntrospectTokenValidator(BaseIntrospectTokenValidator):
        """Validates a token using introspection."""

        def introspect_token(self, token_string):
            """Return the token introspection result."""
            #oauth = g._oidc_auth
            metadata = oauth.keycloak.load_server_metadata()
            if "introspection_endpoint" not in metadata:
                raise RuntimeError(
                    "Can't validate the token because the server does not support "
                    "introspection."
                )
            with oauth.keycloak._get_oauth_client(**metadata) as session:
                response = session.introspect_token(
                    metadata["introspection_endpoint"], token=token_string
                )
            return response.json()

    require_oauth.register_token_validator(IntrospectTokenValidator())

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
        return oauth.keycloak.authorize_redirect(redirect_uri)
    
    # @app.before_request
    # def add_access_token():
    #     if session.get('access_token'):
    #         request.headers['Authorization'] = 'Bearer ' + session.get('access_token')

    @app.route('/authorize')
    def authorize():
        token = oauth.keycloak.authorize_access_token()
        session['user'] = token['userinfo']
        session['access_token'] = token['access_token']
        return redirect('/')
    
    @app.route('/uebersicht')
    @require_oauth(scopes=['email'])
    def uebersicht():
        return "Uebersicht"

    @app.route('/testendpoint')
    @require_oauth(scopes=['email'])
    def testendpoint():
        return jsonify("Test-Endpoint")

    return app

if __name__ == '__main__':
    app = create_app_oauth()
    app.run()