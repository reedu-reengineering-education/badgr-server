import urllib
import urlparse

from allauth.socialaccount.providers.base import AuthProcess
from django.contrib.auth import logout
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse, NoReverseMatch
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.views.generic import RedirectView
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import AuthenticationFailed
import requests

from badgeuser.models import CachedEmailAddress, BadgeUser
from badgrsocialauth.models import Saml2Account, Saml2Configuration
from badgrsocialauth.utils import (set_session_badgr_app, get_session_badgr_app,
                                   get_session_verification_email, set_session_authcode,)
from django.conf import settings
from mainsite.models import BadgrApp
from mainsite.utils import set_url_query_params

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from mainsite.models import AccessTokenProxy


class BadgrSocialLogin(RedirectView):
    def get(self, request, *args, **kwargs):
        try:
            logout(request)
            return super(BadgrSocialLogin, self).get(request, *args, **kwargs)
        except ValidationError as e:
            return HttpResponseBadRequest(e.message)
        except AuthenticationFailed as e:
            return HttpResponseForbidden(e.detail)

    def get_redirect_url(self):
        provider_name = self.request.GET.get('provider', None)
        if provider_name is None:
            raise ValidationError('No provider specified')

        badgr_app = BadgrApp.objects.get_current(request=self.request)
        if badgr_app is not None:
            set_session_badgr_app(self.request, badgr_app)
        else:
            raise ValidationError('Unable to save BadgrApp in session')
        
        self.request.session['source'] = self.request.GET.get('source', None)

        try:
            if 'saml2' in provider_name:
                redirect_url = reverse('saml2login', args=[provider_name])
            else:
                redirect_url = reverse('{}_login'.format(provider_name))
        except NoReverseMatch:
            raise ValidationError('No {} provider found'.format(provider_name))

        authcode = self.request.GET.get('authCode', None)
        if authcode is not None:
            set_session_authcode(self.request, authcode)
            return set_url_query_params(redirect_url, process=AuthProcess.CONNECT)
        else:
            return redirect_url


class BadgrSocialLoginCancel(RedirectView):
    def get_redirect_url(self):
        badgr_app = BadgrApp.objects.get_current(self.request)
        if badgr_app is not None:
            return set_url_query_params(badgr_app.ui_login_redirect)


class BadgrSocialEmailExists(RedirectView):
    def get_redirect_url(self):
        badgr_app = BadgrApp.objects.get_current(self.request)
        if badgr_app is not None:
            return set_url_query_params(badgr_app.ui_login_redirect,
                                        authError='An account already exists with provided email address')


class BadgrSocialAccountVerifyEmail(RedirectView):
    def get_redirect_url(self):
        badgr_app = BadgrApp.objects.get_current(self.request)
        verification_email = get_session_verification_email(self.request)

        if verification_email is not None:
            verification_email = urllib.quote(verification_email.encode('utf-8'))
        else:
            verification_email = ''

        if badgr_app is not None:
            return urlparse.urljoin(badgr_app.ui_signup_success_redirect.rstrip('/') + '/', verification_email)


class BadgrAccountConnected(RedirectView):
    def get_redirect_url(self):
        badgr_app = BadgrApp.objects.get_current(self.request)
        if badgr_app is not None:
            return set_url_query_params(badgr_app.ui_connect_success_redirect)
"""

SAML2 Authentication Flow 

"""

def saml2_client_for(idp_name=None):
    '''
    Given the name of an Identity Provider look up the Saml2Configuration and build a SAML Client. Return these.
    '''

    origin = getattr(settings, 'HTTP_ORIGIN').split('://')[1]
    acs_url = 'http://' + origin + reverse('assertion_consumer_service', args=[idp_name])
    https_acs_url = 'https://' + origin + reverse('assertion_consumer_service', args=[idp_name])

    # SAML metadata changes very rarely.
    try:
        config = Saml2Configuration.objects.get(slug=idp_name)
    except Saml2Configuration.DoesNotExist:
        raise Exception("Saml2Configuration for IDP '{}' not found".format(idp_name))
    try:
        if not config.cached_metadata:
            rv = requests.get(config.metadata_conf_url)
        else:
            rv = config.cached_metadata
    except:
        raise Exception("Could not fetch Saml2Configuration.metadata_conf_url: {}".format(config.metadata_conf_url))

    setting = {
        'metadata': {
            'inline': [rv.text],
        },
        'entityid': "badgrserver",
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_POST),
                        (https_acs_url, BINDING_HTTP_POST)
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
    spConfig.load(setting)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client, config


@csrf_exempt
def assertion_consumer_service(request, idp_name):
    saml_client, config = saml2_client_for(idp_name)
    authn_response = saml_client.parse_authn_request_response(
        request.POST.get('SAMLResponse'),
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    email = user_info.text
    first_name = authn_response.ava['FirstName'][0]
    last_name = authn_response.ava['LastName'][0]
    badgr_app = BadgrApp.objects.get(pk=request.session.get('badgr_app_pk'))
    return auto_provision(request, email, first_name, last_name, badgr_app, config)


def auto_provision(request, email, first_name, last_name, badgr_app, config):
    def login(user):
        accesstoken = AccessTokenProxy.objects.generate_new_token_for_user(
            user,
            scope='rw:backpack rw:profile rw:issuer')
        params = dict(authToken=accesstoken.token)
        return redirect(set_url_query_params(badgr_app.ui_login_redirect, **params))

    def new_account(email):
        new_user = BadgeUser.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            request=request,
        )
        # Auto verify emails
        cached_email = CachedEmailAddress.objects.get(email=email)
        cached_email.verified = True
        cached_email.save()
        Saml2Account.objects.create(config=config, user=new_user, uuid=email)
        return new_user

    # Get/Create account and redirect with token or with error message
    saml2_account = Saml2Account.objects.filter(uuid=email).first()
    if saml2_account:
        return login(saml2_account.user)

    try:
        existing_email = CachedEmailAddress.cached.get(email=email)
        if not existing_email.verified:
            # Email exists but is not verified, auto-provision account and log in
            return login(new_account(email))
        # Email exists and is already verified
        return redirect("{url}?authError={message}".format(
            url=badgr_app.ui_login_redirect,
            message=urllib.quote("Authentication Error")))
    except CachedEmailAddress.DoesNotExist:
        # Email does not exist, auto-provision account and log in
        return login(new_account(email))

def saml2_redirect(request, idp_name):
    saml_client, _ = saml2_client_for(idp_name)
    reqid, info = saml_client.prepare_for_authenticate()
    redirect_url = None
    # Select the IdP URL to send the AuthN request to
    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
    response = redirect(redirect_url)
    #  Read http://stackoverflow.com/a/5494469 and
    #  http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    #  We set those headers here as a "belt and suspenders" approach.
    response['Cache-Control'] = 'no-cache, no-store'
    response['Pragma'] = 'no-cache'
    badgr_app = BadgrApp.objects.get_current(request)
    request.session['badgr_app_pk'] = badgr_app.pk
    return response



