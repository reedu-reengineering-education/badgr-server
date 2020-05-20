import urllib
import urlparse

from saml2.metadata import create_metadata_string

from allauth.account.adapter import get_adapter
from allauth.socialaccount.providers.base import AuthProcess
from django.contrib.auth import logout
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.core.urlresolvers import reverse, NoReverseMatch
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponse
from django.views.generic import RedirectView
from django.shortcuts import redirect, render_to_response
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

import logging

import requests

import base64

from badgeuser.authcode import authcode_for_accesstoken
from badgeuser.models import CachedEmailAddress, BadgeUser
from badgrsocialauth.models import Saml2Account, Saml2Configuration
from badgrsocialauth.utils import (set_session_badgr_app, get_session_badgr_app,
                                   get_session_verification_email, set_session_authcode,)
from django.conf import settings
from mainsite.models import BadgrApp
from mainsite.utils import set_url_query_params

from saml2 import (
    BINDING_HTTP_POST,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from mainsite.models import AccessTokenProxy

logger = logging.getLogger(__name__)

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
        except (NoReverseMatch, TypeError,):
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
            verification_email = self.request.session.get('verification_email', '')
            provider = self.request.session.get('socialaccount_sociallogin', {}).get('account', {}).get('provider', '')
            return set_url_query_params(
                badgr_app.ui_signup_failure_redirect,
                authError='An account already exists with provided email address',
                email=base64.urlsafe_b64encode(verification_email),
                socialAuthSlug=provider
            )


class BadgrSocialAccountVerifyEmail(RedirectView):
    def get_redirect_url(self):
        badgr_app = BadgrApp.objects.get_current(self.request)
        verification_email = get_session_verification_email(self.request)

        if verification_email is not None:
            verification_email = urllib.quote(verification_email.encode('utf-8'))
        else:
            verification_email = ''

        if badgr_app is not None:
            base_64_email = base64.urlsafe_b64encode(verification_email)
            return urlparse.urljoin(badgr_app.ui_signup_success_redirect.rstrip('/') + '/', base_64_email)


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
    config = Saml2Configuration.objects.get(slug=idp_name)
    saml_config = create_saml_config_for(config)
    spConfig = Saml2Config()
    spConfig.load(saml_config)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client, config


def create_saml_config_for(config):
    # SAML metadata changes very rarely, check for cached version first
    should_sign_authn_request = config.use_signed_authn_request

    metadata = None
    if config:
        metadata = config.cached_metadata

    if not metadata:
        r = requests.get(config.metadata_conf_url)
        metadata = r.text

    origin = getattr(settings, 'HTTP_ORIGIN')
    https_acs_url = origin + reverse('assertion_consumer_service', args=[config.slug])

    setting = {
        'metadata': {
            'inline': [metadata],
        },
        'entityid': https_acs_url,
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (https_acs_url, BINDING_HTTP_POST)
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                'authn_requests_signed': should_sign_authn_request,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }
    if should_sign_authn_request:
        key_file = getattr(settings, 'SAML_KEY_FILE', None)
        if key_file is None:
            raise ImproperlyConfigured(
                "Signed Authn request requires the path to a PEM formatted file containing the certificates private key")

        cert_file = getattr(settings, 'SAML_CERT_FILE', None)
        if cert_file is None:
            raise ImproperlyConfigured(
                "Signed Authn request requires the path to a PEM formatted file containing the certificates public key")

        xmlsec_binary_path = getattr(settings, 'XMLSEC_BINARY_PATH', None)
        if xmlsec_binary_path is None:
            raise ImproperlyConfigured(
                "Signed Authn request requires the path to the xmlsec binary")

        setting['key_file'] = key_file
        setting['cert_file'] = cert_file
        # requires xmlsec binaries per https://pysaml2.readthedocs.io/en/latest/examples/sp.html
        setting['xmlsec_binary'] = xmlsec_binary_path
    return setting


def saml2_sp_metadata(request, idp_name):
    config = Saml2Configuration.objects.get(slug=idp_name)
    saml_config = create_saml_config_for(config)
    spConfig = Saml2Config()
    spConfig.load(saml_config)

    metadata = create_metadata_string('', config=spConfig, sign=True)
    return HttpResponse(metadata, content_type="text/xml")


def saml2_render_or_redirect(request, idp_name):
    config = Saml2Configuration.objects.get(slug=idp_name)
    saml_client, _ = saml2_client_for(idp_name)
    response = None

    if config.use_signed_authn_request:
        reqid, info = saml_client.prepare_for_authenticate(
            binding=BINDING_HTTP_POST,
            sign=True
        )
        response = HttpResponse(info['data'])
    else:
        reqid, info = saml_client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
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


@csrf_exempt
def assertion_consumer_service(request, idp_name):
    saml_client, config = saml2_client_for(idp_name)
    try:
        authn_response = saml_client.parse_authn_request_response(
            request.POST.get('SAMLResponse'),
            entity.BINDING_HTTP_POST)
    except Exception as e:
        error = "assertion_consumer_service: saml_client entityid:{}, reponse: {}".format(
            saml_client.config.entityid,
            request.POST.get('SAMLResponse')
        )
        logger.error(error)
        raise e

    authn_response.get_identity()
    if len(set(settings.SAML_EMAIL_KEYS) & set(authn_response.ava.keys())) == 0:
        raise ValidationError('Missing email in SAML assertions, received {}'.format(authn_response.ava.keys()))
    if len(set(settings.SAML_FIRST_NAME_KEYS) & set(authn_response.ava.keys())) == 0:
        raise ValidationError('Missing first_name in SAML assertions, received {}'.format(authn_response.ava.keys()))
    if len(set(settings.SAML_LAST_NAME_KEYS) & set(authn_response.ava.keys())) == 0:
        raise ValidationError('Missing last_name in SAML assertions, received {}'.format(authn_response.ava.keys()))
    email = [authn_response.ava[key][0] for key in settings.SAML_EMAIL_KEYS if key in authn_response.ava][0]
    first_name = [authn_response.ava[key][0] for key in settings.SAML_FIRST_NAME_KEYS if key in authn_response.ava][0]
    last_name = [authn_response.ava[key][0] for key in settings.SAML_LAST_NAME_KEYS if key in authn_response.ava][0]
    badgr_app = BadgrApp.objects.get(pk=request.session.get('badgr_app_pk'))
    return auto_provision(request, email, first_name, last_name, badgr_app, config, idp_name)


def auto_provision(request, email, first_name, last_name, badgr_app, config, idp_name):
    def login(user):
        accesstoken = AccessTokenProxy.objects.generate_new_token_for_user(
            user,
            scope='rw:backpack rw:profile rw:issuer')

        if badgr_app.use_auth_code_exchange:
            authcode = authcode_for_accesstoken(accesstoken)
            params = dict(authCode=authcode)
        else:
            params = dict(authToken=accesstoken.token)
        return redirect(set_url_query_params(badgr_app.ui_login_redirect, **params))

    def new_account(requested_email):
        new_user = BadgeUser.objects.create(
            email=requested_email,
            first_name=first_name,
            last_name=last_name,
            request=request,
            send_confirmation=False
        )
        # Auto verify emails
        cached_email = CachedEmailAddress.objects.get(email=requested_email)
        cached_email.verified = True
        cached_email.save()
        Saml2Account.objects.create(config=config, user=new_user, uuid=requested_email)
        return new_user

    # Get/Create account and redirect with token or with error message
    saml2_account = Saml2Account.objects.filter(uuid=email, config=config).first()
    if saml2_account:
        return login(saml2_account.user)

    try:
        existing_email = CachedEmailAddress.cached.get(email=email)
        if not existing_email.verified:
            # Email exists but is not verified, auto-provision account and log in
            new_account = new_account(email)
            return login(new_account)
        elif existing_email.verified:
            # Email exists and is already verified
            url = set_url_query_params(
                badgr_app.ui_signup_failure_redirect,
                authError='An account already exists with provided email address',
                email=base64.urlsafe_b64encode(email),
                socialAuthSlug=idp_name
            )
            return redirect(url)
    except CachedEmailAddress.DoesNotExist:
        # Email does not exist, auto-provision account and log in
        return login(new_account(email))
