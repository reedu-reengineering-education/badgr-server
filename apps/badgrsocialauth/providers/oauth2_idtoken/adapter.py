import json
import jwcrypto.jwk as jwk
import python_jwt as jwt

from datetime import datetime, timedelta
import requests
import logging

from allauth.compat import parse_qsl
from allauth.socialaccount import app_settings
from allauth.socialaccount.models import SocialToken
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter, OAuth2CallbackView, OAuth2LoginView)
from allauth.socialaccount.providers.oauth2.client import OAuth2Client, OAuth2Error

from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from socialauth.providers.log_configuration import debug_requests
from .provider import IdTokenProvider


logger = logging.getLogger(__name__)


class IdTokenOAuth2Adapter(OAuth2Adapter):
    provider_id = None  # override with Provider.id
    supports_state = False
    redirect_uri_protocol = 'https'

    def __init__(self, request):
        super(IdTokenOAuth2Adapter, self).__init__(request)
        try:
            self.access_token_url = app_settings.PROVIDERS[self.provider_id]['access_token_url']
            self.authorize_url = app_settings.PROVIDERS[self.provider_id]['authorize_url']
            self.jwks_url = app_settings.PROVIDERS[self.provider_id]['jwks_url']
            self.intended_aud = app_settings.PROVIDERS[self.provider_id]['aud']
        except KeyError as e:
            raise ImproperlyConfigured(self.provider_id)

    def get_public_key(self, kid=None):
        try:
            # TODO fetch jwks url only if not cached
            jwks = requests.get(self.jwks_url).json()
            available_keys = jwks['keys']

            if kid is not None:
                key = [key for key in available_keys if key.get('kid') == kid][0]
            else:
                key = available_keys[0]

            return jwk.JWK.from_json(json.dumps(key))

        except (TypeError, KeyError, IndexError) as e:
            raise OAuth2Error("Couldn't get JWKS File and process it: {}".format(e.message))

    def parse_token(self, data):
        # parse token header and get relevant public key
        unverified_header, unverified_claims = jwt.process_jwt(data['id_token'])
        public_key = self.get_public_key(unverified_header.get('kid'))

        # verify signature, iat, exp
        header, claims = jwt.verify_jwt(data['id_token'], public_key, ['RS256'], timedelta(minutes=1))

        # verify we are the aud
        if self.intended_aud != claims.get('aud'):
            raise OAuth2Error("JTW aud {} does not match intended audience {}".format(
                claims.get('aud'), self.intended_aud)
            )

        social_token = SocialToken(token=data['id_token'])
        social_token.expires_at = datetime.fromtimestamp(claims['iat'], tz=timezone.utc)
        return social_token

    def complete_login(self, request, app, token, **kwargs):
        # token has already been verified, so we can use unverified data here
        unverified_header, unverified_claims = jwt.process_jwt(token.token)
        extra_data = unverified_claims
        logger.debug('IHRPSSO | IHRPOAuth2Adapter:complete_login()'
                     'token claims |  %s' % str(extra_data))

        return self.get_provider().sociallogin_from_response(request,
                                                             extra_data)


class IdTokenOAuth2Client(OAuth2Client):
    def get_access_token(self, code):
        data = {
            'redirect_uri': self.callback_url,
            'grant_type': 'authorization_code',
            'code': code}
        if self.basic_auth:
            auth = requests.auth.HTTPBasicAuth(
                self.consumer_key,
                self.consumer_secret)
        else:
            auth = None
            data.update({
                'client_id': self.consumer_key,
                'client_secret': self.consumer_secret
            })
        params = None
        self._strip_empty_keys(data)
        url = self.access_token_url
        if self.access_token_method == 'GET':
            params = data
            data = None
        # TODO: Proper exception handling
        resp = requests.request(
            self.access_token_method,
            url,
            params=params,
            data=data,
            headers=self.headers,
            auth=auth)

        access_token = None
        if resp.status_code in [200, 201]:
            # Weibo sends json via 'text/plain;charset=UTF-8'
            if resp.headers['content-type'].split(';')[0] == 'application/json' or resp.text[:2] == '{"':
                access_token = resp.json()
            else:
                access_token = dict(parse_qsl(resp.text))
        if not access_token or 'id_token' not in access_token:
            raise OAuth2Error('Error retrieving access token: %s'
                              % resp.content)
        return access_token


class IHRPOAuth2CallbackView(OAuth2CallbackView):
    def get_client(self, request, app):
        callback_url = self.adapter.get_callback_url(request, app)
        provider = self.adapter.get_provider()
        scope = provider.get_scope(request)
        client = IdTokenOAuth2Client(self.request, app.client_id, app.secret,
                              self.adapter.access_token_method,
                              self.adapter.access_token_url,
                              callback_url,
                              scope,
                              scope_delimiter=self.adapter.scope_delimiter,
                              headers=self.adapter.headers,
                              basic_auth=self.adapter.basic_auth)
        return client


oauth2_login = OAuth2LoginView.adapter_view(IdTokenOAuth2Adapter)
base_oauth2_callback = IHRPOAuth2CallbackView.adapter_view(IdTokenOAuth2Adapter)
def oauth2_callback(*args, **kwargs):
    with debug_requests():
        return base_oauth2_callback(*args, **kwargs)
