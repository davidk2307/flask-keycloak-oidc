import os
import json
from flask import Flask,session
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

if __name__ == '__main__':
    app = create_app()
    app.run()