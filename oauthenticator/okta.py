"""
Custom Authenticator to use Okta OAuth with JupyterHub

Derived using the Github and Google OAuthenticator implementations as examples.

The following environment variables may be used for configuration:

    OKTA_SUBDOMAIN - The subdomain for your Okta account
    OAUTH_CLIENT_ID - Your client id
    OAUTH_CLIENT_SECRET - Your client secret
    OAUTH_CALLBACK_URL - Your callback handler URL

Additionally, if you are concerned about your secrets being exposed by
an env dump(I know I am!) you can set the client_secret, client_id and
oauth_callback_url directly on the config for OktaOAuthenticator.

One instance of this could be adding the following to your jupyterhub_config.py :

  c.OktaOAuthenticator.client_id = 'YOUR_CLIENT_ID'
  c.OktaOAuthenticator.client_secret = 'YOUR_CLIENT_SECRET'
  c.OktaOAuthenticator.oauth_callback_url = 'YOUR_CALLBACK_URL'

If you are using the environment variable config, all you should need to
do is define them in the environment then add the following line to
jupyterhub_config.py :

  c.JupyterHub.authenticator_class = 'oauthenticator.Okta.OktaOAuthenticator'

"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator

OKTA_SUBDOMAIN = os.getenv('OKTA_SUBDOMAIN')

class OktaMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s.oktapreview.com/oauth2/v1/authorize" % OKTA_SUBDOMAIN
    _OAUTH_ACCESS_TOKEN_URL = "https://%s.oktapreview.com/oauth2/v1/token" % OKTA_SUBDOMAIN


class OktaLoginHandler(OAuthLoginHandler, OktaMixin):
    pass

class OktaOAuthenticator(OAuthenticator):

    login_service = "Okta"

    login_handler = OktaLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):

        print(handler)
        code = handler.get_argument("code")

        print(code)
        print('code above ' )

        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code':code,
            'redirect_uri': self.get_callback_url(handler)
        }

        callbackurl = 'http%3A%2F%2Fopenig.example.com'
        paramsdata = 'grant_type=authorization_code&redirect_uri='+callbackurl+'%3A8000%2Fhub%2Foauth_callback&code='
        paramsdata += code + '&client_id=' + self.client_id + '&client_secret=' + self.client_secret;

        url = "https://%s.oktapreview.com/oauth2/v1/token" % OKTA_SUBDOMAIN

        print('url for token here : ')
        print(url)

        print(paramsdata)
        # t = json.dumps(params)
        # print(t)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body=paramsdata
                          )


        # print(json.dumps(req))
        print(' before fetcing resp')
        resp = yield http_client.fetch(req)

        print(resp)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))


        print(resp_json)
        print(' above resp what now ')

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("https://%s.oktapreview.com/oauth2/v1/userinfo" % OKTA_SUBDOMAIN,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        print(resp_json['name'])

        print(' for okta now please ')
        print(resp_json)

        return {
            'name': resp_json['name'],
            'auth_state': {
                'access_token': access_token,
                'okta_user': resp_json,
            }
        }


class LocalOktaOAuthenticator(LocalAuthenticator, OktaOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
