# -*- coding: utf-8 -*-
# Copyright 2015 Okta, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import os
import uuid

import flask_login
import requests
import saml2
from flask import Flask, redirect, render_template, request, session, url_for
from flask_bootstrap import Bootstrap
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

# metadata_url_for contains PER APPLICATION configuration settings.
# Each SAML service that you support will have different values here.
#
# NOTE:
#   This is implemented as a dictionary for DEMONSTRATION PURPOSES ONLY.
#   On a production system, this information should be stored as approprate
#   for your concept of "customer company", "group", "organization", or "team"
metadata_url_for = {
    # For testing with http://saml.oktadev.com use the following:
    # 'test': 'http://idp.oktadev.com/metadata',
    # WARNING WARNING WARNING
    #   You MUST remove the testing IdP from a production system,
    #   as the testing IdP will allow ANYBODY to log in as ANY USER!
    # WARNING WARNING WARNING
    'example-okta-com': 'https://dev-149840.oktapreview.com/app/exkjevrol78BxCNm90h7/sso/saml/metadata'
}

app = Flask(__name__)
Bootstrap(app)
app.secret_key = str(uuid.uuid4())  # Replace with your secret key
login_manager = flask_login.LoginManager()
login_manager.setup_app(app)
logging.basicConfig(level=logging.DEBUG)
# NOTE:
#   This is implemented as a dictionary for DEMONSTRATION PURPOSES ONLY.
#   On a production system, this information must come
#   from your system's user store.
user_store = {}


def saml_client_for(idp_name=None):
    '''
    Given the name of an IdP, return a configuation.
    The configuration is a hash for use by saml2.config.Config
    '''

    if idp_name not in metadata_url_for:
        raise Exception("Settings for IDP '{}' not found".format(idp_name))

    # acs: assertion consumer service
    # url_for takes the view function name
    # http://localhost:5000/saml/sso/example-okta-com
    acs_url = url_for("idp_initiated", idp_name=idp_name, _external=True)
    # https://localhost:5000/saml/sso/example-okta-com
    https_acs_url = url_for("idp_initiated", idp_name=idp_name, _external=True, _scheme='https')

    #   SAML metadata changes very rarely. On a production system,
    #   this data should be cached as approprate for your production system.
    rv = requests.get(metadata_url_for[idp_name])

    settings = {
        'entityid': 'https://example.com/sp/metadata',
        'metadata': {
            'inline': [rv.text],
            },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, saml2.BINDING_HTTP_REDIRECT),
                        (acs_url, saml2.BINDING_HTTP_POST),
                        (https_acs_url, saml2.BINDING_HTTP_REDIRECT),
                        (https_acs_url, saml2.BINDING_HTTP_POST)
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                # Don't sign authn requests, since signed requests only make
                # sense in a situation where you control both the SP and IdP
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }

    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True

    return Saml2Client(config=spConfig)


class User(flask_login.UserMixin):
    def __init__(self, user_id):
        user = {}
        self.id = None
        self.first_name = None
        self.last_name = None
        try:
            user = user_store[user_id]
            self.id = unicode(user_id)
            self.first_name = user['first_name']
            self.last_name = user['last_name']
        except:
            pass


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route("/")
def main_page():
    return render_template('main_page.html', idp_dict=metadata_url_for)

# ACS Endpoint – Assertion Consumer Service URL – often referred to simply as the SP login URL.
# This is the endpoint provided by the SP where SAML responses are posted.
# The SP needs to provide this information to the IDP.
@app.route("/saml/sso/<idp_name>", methods=['POST'])
def idp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)

    # request.form has two fields: SAMLResponse and RelayState
    authn_response = saml_client.parse_authn_request_response(request.form['SAMLResponse'], saml2.entity.BINDING_HTTP_POST)

    authn_response.get_identity()
    user_info = authn_response.get_subject()
    username = user_info.text

    # This is what as known as "Just In Time (JIT) provisioning".
    # What that means is that, if a user in a SAML assertion
    # isn't in the user store, we create that user first, then log them in
    if username not in user_store:
        user_store[username] = {
            'first_name': authn_response.ava['FirstName'][0],
            'last_name': authn_response.ava['LastName'][0],
            }
    user = User(username)
    session['saml_attributes'] = authn_response.ava
    flask_login.login_user(user)
    url = url_for('user')
    print('************** url', url)
    # NOTE:
    #   On a production system, the RelayState MUST be checked
    #   to make sure it doesn't contain dangerous URLs!
    if 'RelayState' in request.form:
        # 'RelayState' is in the response but it is empty.
        url = request.form['RelayState']

    print('************** url', url)
    # url is empty so it goes to the home page.
    return redirect(url)


@app.route("/saml/login/<idp_name>")
def sp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)
    # Makes all necessary preparations for an authentication request
    _, info = saml_client.prepare_for_authenticate()

    redirect_url = None
    # Select the IdP URL to send the AuthN request to
    for key, value in info['headers']:
        if key is 'Location':
            redirect_url = value

    response = redirect(redirect_url, code=302)
    # NOTE:
    #   I realize I _technically_ don't need to set Cache-Control or Pragma:
    #     http://stackoverflow.com/a/5494469
    #   However, Section 3.2.3.2 of the SAML spec suggests they are set:
    #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    #   We set those headers here as a "belt and suspenders" approach,
    #   since enterprise environments don't always conform to RFCs
    response.headers['Cache-Control'] = 'no-cache, no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route("/user")
@flask_login.login_required
def user():
    return render_template('user.html', session=session)


@app.errorhandler(401)
def error_unauthorized(error):
    return render_template('unauthorized.html')


@app.route("/logout")
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return redirect(url_for("main_page"))

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    if port == 5000:
        app.debug = True
    app.run(host='0.0.0.0', port=port)
