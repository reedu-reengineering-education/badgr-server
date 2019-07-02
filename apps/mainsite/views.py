import base64
import time

from django import forms
from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.core.urlresolvers import reverse_lazy, reverse
from django.db import IntegrityError
from django.http import (HttpResponse, HttpResponseServerError,
                         HttpResponseNotFound, HttpResponseRedirect)
from django.shortcuts import redirect
from django.template import loader, TemplateDoesNotExist, Context
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.generic import FormView, RedirectView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import AllowAny
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from mainsite.utils import set_url_query_params
from issuer.tasks import rebake_all_assertions, update_issuedon_all_assertions
from mainsite.admin_actions import clear_cache
from mainsite.models import EmailBlacklist, BadgrApp, AccessTokenProxy
from mainsite.serializers import VerifiedAuthTokenSerializer
from pathway.tasks import resave_all_elements
from badgrsocialauth.models import Saml2Configuration, Saml2Account
from badgeuser.models import BadgeUser, CachedEmailAddress
import urllib

##
#
#  Error Handler Views
#
##
@xframe_options_exempt
def error404(request):
    try:
        template = loader.get_template('error/404.html')
    except TemplateDoesNotExist:
        return HttpResponseServerError('<h1>Page not found (404)</h1>', content_type='text/html')
    return HttpResponseNotFound(template.render({
        'STATIC_URL': getattr(settings, 'STATIC_URL', '/static/'),
    }))


@xframe_options_exempt
def error500(request):
    try:
        template = loader.get_template('error/500.html')
    except TemplateDoesNotExist:
        return HttpResponseServerError('<h1>Server Error (500)</h1>', content_type='text/html')
    return HttpResponseServerError(template.render({
        'STATIC_URL': getattr(settings, 'STATIC_URL', '/static/'),
    }))


def info_view(request):
    return redirect(getattr(settings, 'LOGIN_REDIRECT_URL'))


def email_unsubscribe_response(request, message, error=False):
    badgr_app_pk = request.GET.get('a', getattr(settings, 'BADGR_APP_ID', None))
    try:
        badgr_app = BadgrApp.objects.get(pk=badgr_app_pk)
    except BadgrApp.DoesNotExist:
        pass

    if badgr_app:
        query_param = 'infoMessage' if error else 'authError'
        redirect_url = "{url}?{query_param}={message}".format(
            url=badgr_app.ui_login_redirect,
            query_param=query_param,
            message=message)
        return HttpResponseRedirect(redirect_to=redirect_url)
    else:
        return HttpResponse(message)


def email_unsubscribe(request, *args, **kwargs):
    if time.time() > int(kwargs['expiration']):
        return email_unsubscribe_response(
            request, 'Your unsubscription link has expired.', error=True)

    try:
        email = base64.b64decode(kwargs['email_encoded'])
    except TypeError:
        return email_unsubscribe_response(request, 'Invalid unsubscribe link.',
                                          error=True)

    if not EmailBlacklist.verify_email_signature(**kwargs):
        return email_unsubscribe_response(request, 'Invalid unsubscribe link.',
                                          error=True)

    blacklist_instance = EmailBlacklist(email=email)
    try:
        blacklist_instance.save()
    except IntegrityError:
        pass

    return email_unsubscribe_response(
        request, "You will no longer receive email notifications for earned"
        " badges from this domain.")


class AppleAppSiteAssociation(APIView):
    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)

    def get(self, request):
        data = {
            "applinks": {
                "apps": [],
                "details": []
            }
        }

        for app_id in getattr(settings, 'APPLE_APP_IDS', []):
            data['applinks']['details'].append(app_id)

        return Response(data=data)


class LoginAndObtainAuthToken(ObtainAuthToken):
    serializer_class = VerifiedAuthTokenSerializer


class SitewideActionForm(forms.Form):
    ACTION_CLEAR_CACHE = 'CLEAR_CACHE'
    ACTION_RESAVE_ELEMENTS = 'RESAVE_ELEMENTS'
    ACTION_REBAKE_ALL_ASSERTIONS = "REBAKE_ALL_ASSERTIONS"
    ACTION_FIX_ISSUEDON = 'FIX_ISSUEDON'

    ACTIONS = {
        ACTION_CLEAR_CACHE: clear_cache,
        ACTION_RESAVE_ELEMENTS: resave_all_elements,
        ACTION_REBAKE_ALL_ASSERTIONS: rebake_all_assertions,
        ACTION_FIX_ISSUEDON: update_issuedon_all_assertions,
    }
    CHOICES = (
        (ACTION_CLEAR_CACHE, 'Clear Cache',),
        (ACTION_RESAVE_ELEMENTS, 'Re-save Pathway Elements',),
        (ACTION_REBAKE_ALL_ASSERTIONS, 'Rebake all assertions',),
        (ACTION_FIX_ISSUEDON, 'Re-process issuedOn for backpack assertions',),
    )

    action = forms.ChoiceField(choices=CHOICES, required=True, label="Pick an action")
    confirmed = forms.BooleanField(required=True, label='Are you sure you want to perform this action?')


class SitewideActionFormView(FormView):
    form_class = SitewideActionForm
    template_name = 'admin/sitewide_actions.html'
    success_url = reverse_lazy('admin:index')

    @method_decorator(staff_member_required)
    def dispatch(self, request, *args, **kwargs):
        return super(SitewideActionFormView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        action = form.ACTIONS[form.cleaned_data['action']]

        if hasattr(action, 'delay'):
            action.delay()
        else:
            action()

        return super(SitewideActionFormView, self).form_valid(form)


class RedirectToUiLogin(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        badgrapp = BadgrApp.objects.get_current()
        return badgrapp.ui_login_redirect if badgrapp.ui_login_redirect is not None else badgrapp.email_confirmation_redirect


class DocsAuthorizeRedirect(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        badgrapp = BadgrApp.objects.get_current(request=self.request)
        url = badgrapp.oauth_authorization_redirect
        if not url:
            url = 'https://{cors}/auth/oauth2/authorize'.format(cors=badgrapp.cors)

        query = self.request.META.get('QUERY_STRING', '')
        if query:
            url = "{}?{}".format(url, query)
        return url

# Okta Views
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import requests

@csrf_exempt
def assertion_consumer_service(request, idp_name):
    saml_client, config = saml_client_for(idp_name)
    authn_response = saml_client.parse_authn_request_response(
        request.POST.get('SAMLResponse'),
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    email = user_info.text
    try:
        first_name = authn_response.ava['FirstName'][0]
        last_name = authn_response.ava['LastName'][0]
    except:
        raise Exception("Could not get first and/or last name from SAML2 ava")
    try:
        badgr_app = BadgrApp.objects.get(pk=request.session.get('badgr_app_pk'))
    except:
        raise Exception("Could not find badgr_app_pk in session")

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
        email = CachedEmailAddress.objects.get(email=email)
        email.verified = True
        email.save()
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
    saml_client, _ = saml_client_for(idp_name)
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


def saml_client_for(idp_name=None):
    '''
    Given the name of an IdP,
    Look up the ACS url and the metadata
    return a configuation.
    The configuration is a hash for use by saml2.config.Config
    '''

    origin = getattr(settings, 'HTTP_ORIGIN').split('://')[1]
    acs_url = 'http://' + origin + reverse('assertion_consumer_service', args=[idp_name])
    https_acs_url = 'https://' + origin + reverse('assertion_consumer_service', args=[idp_name])

    # SAML metadata changes very rarely.
    # Consider caching this XML instead of requesting from the network everytime
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
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                        (https_acs_url, BINDING_HTTP_REDIRECT),
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
