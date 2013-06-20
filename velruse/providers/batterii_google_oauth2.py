import uuid
# Batterii Google Oauth2 Provider
# Note: This is a fork of the original Velruse Google provider
#
# Changes from the original
#   - We can't use session state so had to remove the XCSRF logic
#   - We need to pass state from original login process to the final call back so we added a client_state param to login
#
## TODO We need to support overriding the static settings on a per account basis at some point...


from pyramid.httpexceptions import HTTPFound
from pyramid.security import NO_PERMISSION_REQUIRED
from pickle import loads, dumps

import requests

from ..api import (
    AuthenticationComplete,
    AuthenticationDenied,
    register_provider,
)
from ..exceptions import CSRFError
from ..exceptions import ThirdPartyFailure
from ..settings import ProviderSettings
from ..utils import flat_url


GOOGLE_OAUTH2_DOMAIN = 'accounts.google.com'


class GoogleAuthenticationComplete(AuthenticationComplete):
    """Google OAuth 2.0 auth complete"""
    def __init__(self,
                 profile=None,
                 credentials=None,
                 provider_name=None,
                 provider_type=None,
                 client_state=None):
        """Create an AuthenticationComplete object with user data"""
        AuthenticationComplete.__init__(self, profile, credentials, provider_name, provider_type)
        self.client_state = client_state

class GoogleAuthenticationDenied(AuthenticationDenied):
    def __init__(self,
                 reason=None,
                 provider_name=None,
                 provider_type=None,
                 client_state=None):
        """Create an AuthenticationDenied object with user data"""
        AuthenticationDenied.__init__(self, reason, provider_name, provider_type)
        self.client_state = client_state

def includeme(config):
    """Activate the ``google_oauth2`` Pyramid plugin via
    ``config.include('velruse.providers.google_oauth2')``. After included,
    two new methods will be available to configure new providers.

    ``config.add_google_oauth2_login()``
        See :func:`~velruse.providers.google_oauth2.add_google_login`
        for the supported options.

    ``config.add_google_oauth2_login_from_settings()``

    """
    config.add_directive('add_google_oauth2_login', add_google_login)
    config.add_directive('add_google_oauth2_login_from_settings',
                         add_google_login_from_settings)

def add_google_login_from_settings(config, prefix='velruse.google.'):
    settings = config.registry.settings
    p = ProviderSettings(settings, prefix)
    p.update('consumer_key', required=True)
    p.update('consumer_secret', required=True)
    p.update('scope')
    p.update('login_path')
    p.update('callback_path')
    config.add_google_oauth2_login(**p.kwargs)

def add_google_login(config,
                     consumer_key=None,
                     consumer_secret=None,
                     scope=None,
                     login_path='/login/google',
                     callback_path='/login/google/callback',
                     name='google'):
    """
    Add a Google login provider to the application supporting the new
    OAuth2 protocol.
    """
    provider = GoogleOAuth2Provider(
        name,
        consumer_key,
        consumer_secret,
        scope)

    config.add_route(provider.login_route, login_path)
    config.add_view(provider, attr='login', route_name=provider.login_route,
                    permission=NO_PERMISSION_REQUIRED)

    config.add_route(provider.callback_route, callback_path,
                     use_global_views=True,
                     factory=provider.callback)

    register_provider(config, name, provider)

class GoogleOAuth2Provider(object):

    profile_scope = 'https://www.googleapis.com/auth/userinfo.profile'
    email_scope = 'https://www.googleapis.com/auth/userinfo.email'

    def __init__(self,
                 name,
                 consumer_key,
                 consumer_secret,
                 scope):
        self.name = name
        self.type = 'batterii_google_oauth2'
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.protocol = 'https'
        self.domain = GOOGLE_OAUTH2_DOMAIN

        self.login_route = 'velruse.%s-login' % name
        self.callback_route = 'velruse.%s-callback' % name

        self.scope = scope
        if not self.scope:
            self.scope = ' '.join((self.profile_scope, self.email_scope))

    def login(self, request):

        if request.POST:
            scope = ' '.join(request.POST.getall('scope')) or self.scope
            approval_prompt = request.POST.get('approval_prompt', 'auto')
            client_state = client_state=request.POST.get('client_state')
        else:
            scope = ' '.join(request.GET.getall('scope')) or self.scope
            approval_prompt = request.GET.get('approval_prompt', 'auto')
            client_state = client_state=request.GET.get('client_state')

        """Initiate a google login"""
        csrf_token = uuid.uuid4().hex
        request.session['csrf_token'] = csrf_token

        state = dict(csrf_token=csrf_token, client_state=client_state)

        auth_url = flat_url(
            '%s://%s/o/oauth2/auth' % (self.protocol, self.domain),
            scope=scope,
            response_type='code',
            client_id=self.consumer_key,
            redirect_uri=request.route_url(self.callback_route),
            approval_prompt=approval_prompt,
            access_type='offline',
            state=dumps(state))
        return HTTPFound(location=auth_url)

    def callback(self, request):
        """Process the google redirect"""
        sess_csrf_token = request.session.get('csrf_token')
        req_state_dict = loads(request.GET.get('state'))

        req_csrf_token = req_state_dict['csrf_token']
        if not sess_csrf_token or sess_csrf_token != req_csrf_token:
            raise CSRFError(
                'CSRF Validation check failed. Request state {req_state} is '
                'not the same as session state {sess_state}'.format(
                    req_state=req_csrf_token,
                    sess_state=sess_csrf_token
                )
            )
        code = request.GET.get('code')
        if not code:
            reason = request.GET.get('error', 'No reason provided.')
            return GoogleAuthenticationDenied(reason=reason,
                                        provider_name=self.name,
                                        provider_type=self.type)

        # Now retrieve the access token with the code
        r = requests.post(
            '%s://%s/o/oauth2/token' % (self.protocol, self.domain),
            dict(client_id=self.consumer_key,
                 client_secret=self.consumer_secret,
                 redirect_uri=request.route_url(self.callback_route),
                 code=code,
                 grant_type='authorization_code'),
        )
        if r.status_code != 200:
            raise ThirdPartyFailure("Status %s: %s" % (
                r.status_code, r.content))
        token_data = r.json()
        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token')

        # Retrieve profile data if scopes allow
        profile = {}
        user_url = flat_url(
            '%s://www.googleapis.com/oauth2/v1/userinfo' % self.protocol,
            access_token=access_token)
        r = requests.get(user_url)

        if r.status_code == 200:
            data = r.json()
            profile['accounts'] = [{
                'domain': self.domain,
                'username': data['email'],
                'userid': data['id']
            }]
            profile['displayName'] = data['name']
            profile['givenName'] = data['given_name']
            profile['familyName'] = data['family_name']
            profile['preferredUsername'] = data['email']
            profile['verifiedEmail'] = data['email']
            profile['imageUrl'] = data['picture']
            profile['emails'] = [{'value': data['email']}]

        cred = {'oauthAccessToken': access_token,
                'oauthRefreshToken': refresh_token}
        return GoogleAuthenticationComplete(profile=profile,
                                            credentials=cred,
                                            provider_name=self.name,
                                            provider_type=self.type,
                                            client_state=req_state_dict['client_state'])
