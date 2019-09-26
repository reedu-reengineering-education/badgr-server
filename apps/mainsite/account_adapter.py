import logging
import urllib
import urlparse

from allauth.account.adapter import DefaultAccountAdapter, get_adapter
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from allauth.account.utils import user_pk_to_url_str
from allauth.exceptions import ImmediateHttpResponse
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.urlresolvers import resolve, Resolver404, reverse
from django.http import HttpResponseRedirect

from badgeuser.authcode import authcode_for_accesstoken
from badgeuser.models import CachedEmailAddress
from badgrsocialauth.utils import get_session_badgr_app, set_session_badgr_app
from mainsite.models import BadgrApp, EmailBlacklist, AccessTokenProxy
from mainsite.utils import OriginSetting, set_url_query_params


class BadgrAccountAdapter(DefaultAccountAdapter):

    def send_mail(self, template_prefix, email, context):
        context['STATIC_URL'] = getattr(settings, 'STATIC_URL')
        context['HTTP_ORIGIN'] = getattr(settings, 'HTTP_ORIGIN')
        context['PRIVACY_POLICY_URL'] = getattr(settings, 'PRIVACY_POLICY_URL', None)
        context['TERMS_OF_SERVICE_URL'] = getattr(settings, 'TERMS_OF_SERVICE_URL', None)
        context['GDPR_INFO_URL'] = getattr(settings, 'GDPR_INFO_URL', None)
        context['OPERATOR_STREET_ADDRESS'] = getattr(settings, 'OPERATOR_STREET_ADDRESS', None)
        context['OPERATOR_NAME'] = getattr(settings, 'OPERATOR_NAME', None)
        context['OPERATOR_URL'] = getattr(settings, 'OPERATOR_URL', None)

        if context.get('unsubscribe_url', None) is None:
            try:
                badgrapp_pk = context['badgr_app'].pk
            except (KeyError, AttributeError):
                badgrapp_pk = None
            context['unsubscribe_url'] = getattr(settings, 'HTTP_ORIGIN') + EmailBlacklist.generate_email_signature(
                email, badgrapp_pk)

        msg = self.render_mail(template_prefix, email, context)
        msg.send()

    def is_open_for_signup(self, request):
        return getattr(settings, 'OPEN_FOR_SIGNUP', True)

    def get_email_confirmation_redirect_url(self, request, badgr_app=None):
        """
        The URL to return to after successful e-mail confirmation.
        """
        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(request)
            if not badgr_app:
                logger = logging.getLogger(self.__class__.__name__)
                logger.warning("Could not determine authorized badgr app")
                return super(BadgrAccountAdapter, self).get_email_confirmation_redirect_url(request)

        try:
            resolver_match = resolve(request.path)
            confirmation = EmailConfirmationHMAC.from_key(resolver_match.kwargs.get('confirm_id'))
            # publish changes to cache
            email_address = CachedEmailAddress.objects.get(pk=confirmation.email_address.pk)
            email_address.save()

            query_params = {
                'email': email_address.email.encode('utf8')
            }
            # Pass source and signup along to UI
            source = request.query_params.get('source', None)
            if source:
                query_params['source'] = source

            signup = request.query_params.get('signup', None)
            if signup:
                query_params['signup'] = 'true'
                return set_url_query_params(badgr_app.get_path('/auth/welcome'), **query_params)
            else:
                return set_url_query_params(urlparse.urljoin(
                    badgr_app.email_confirmation_redirect.rstrip('/') + '/',
                    urllib.quote(email_address.user.first_name.encode('utf8'))
                ), **query_params)

        except Resolver404, EmailConfirmation.DoesNotExist:
            return badgr_app.email_confirmation_redirect

    def get_email_confirmation_url(self, request, emailconfirmation, signup=False):
        url_name = "v1_api_user_email_confirm"
        temp_key = default_token_generator.make_token(emailconfirmation.email_address.user)
        token = "{uidb36}-{key}".format(uidb36=user_pk_to_url_str(emailconfirmation.email_address.user),
                                        key=temp_key)
        activate_url = OriginSetting.HTTP + reverse(url_name, kwargs={'confirm_id': emailconfirmation.key})
        badgrapp = BadgrApp.objects.get_current(request=request)
        tokenized_activate_url = "{url}?token={token}&a={badgrapp}".format(
            url=activate_url,
            token=token,
            badgrapp=badgrapp.id
        )

        # Add source and signup query params to the confimation url
        if request:
            source = None
            if hasattr(request, 'data'):
                source = request.data.get('source', None)
            elif hasattr(request, 'session'):
                source = request.session.get('source', None)

            if source:
                tokenized_activate_url = set_url_query_params(tokenized_activate_url, source=source)

            if signup:
                tokenized_activate_url = set_url_query_params(tokenized_activate_url, signup="true")

        return tokenized_activate_url

    def send_confirmation_mail(self, request, emailconfirmation, signup):
        current_site = get_current_site(request)
        activate_url = self.get_email_confirmation_url(
            request,
            emailconfirmation,
            signup)
        badgr_app = BadgrApp.objects.get_current(request, raise_exception=False)
        ctx = {
            "user": emailconfirmation.email_address.user,
            "email": emailconfirmation.email_address,
            "activate_url": activate_url,
            "current_site": current_site,
            "key": emailconfirmation.key,
            "badgr_app": badgr_app,
        }
        if signup:
            email_template = 'account/email/email_confirmation_signup'
        else:
            email_template = 'account/email/email_confirmation'
        get_adapter().send_mail(email_template,
                                emailconfirmation.email_address.email,
                                ctx)

    def get_login_redirect_url(self, request):
        """
        If successfully logged in, redirect to the front-end, including an authToken query parameter.
        """
        if request.user.is_authenticated():
            badgr_app = BadgrApp.objects.get_current(self.request)

            if badgr_app is not None:
                accesstoken = AccessTokenProxy.objects.generate_new_token_for_user(
                    request.user,
                    application=badgr_app.oauth_application if badgr_app.oauth_application_id else None,
                    scope='rw:backpack rw:profile rw:issuer')

                if badgr_app.use_auth_code_exchange:
                    authcode = authcode_for_accesstoken(accesstoken)
                    params = dict(authCode=authcode)
                else:
                    params = dict(authToken=accesstoken.token)

                return set_url_query_params(badgr_app.ui_login_redirect, **params)
        else:
            return '/'

    def login(self, request, user):
        """
        Guard against unverified users and preserve badgr_app session data
        across Django login() boundary.
        """
        if not user.verified:
            # The usual case if a user gets here without a verified recipient
            # identifier is a new sign-up with an unverified email. If that's
            # the case, we just sent them a confirmation.
            raise ImmediateHttpResponse(
                self.respond_email_verification_sent(request, user))

        badgr_app = BadgrApp.objects.get_current(request)
        ret = super(BadgrAccountAdapter, self).login(request, user)
        set_session_badgr_app(request, badgr_app)
        return ret

    def respond_email_verification_sent(self, request, user):
        badgr_app = BadgrApp.objects.get_current(request)
        return HttpResponseRedirect(badgr_app.signup_redirect)
