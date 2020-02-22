import importlib
import logging

from allauth.socialaccount import providers
from django.conf.urls import url

from badgrsocialauth.views import BadgrSocialLogin, BadgrSocialEmailExists, BadgrSocialAccountVerifyEmail, \
    BadgrSocialLoginCancel, BadgrAccountConnected, saml2_redirect, assertion_consumer_service

urlpatterns = [
    url(r'^sociallogin', BadgrSocialLogin.as_view(permanent=False), name='socialaccount_login'),

    # Intercept allauth cancel login view
    url(r'^cancellogin', BadgrSocialLoginCancel.as_view(permanent=False), name='socialaccount_login_cancelled'),

    # Intercept allauth signup view (if account with given email already exists) and redirect to UI
    url(r'^emailexists', BadgrSocialEmailExists.as_view(permanent=False), name='socialaccount_signup'),

    # Intercept allauth email verification view and redirect to UI
    url(r'^verifyemail', BadgrSocialAccountVerifyEmail.as_view(permanent=False), name='account_email_verification_sent'),

    # Intercept allauth connections view (attached a new social account)
    url(r'^connected', BadgrAccountConnected.as_view(permanent=False), name='socialaccount_connections'),

    # SAML2 Identity Provider
    url(r'^saml2/(?P<idp_name>[\w\.\-]+)/$', saml2_redirect, name='saml2login'),
    url(r'^saml2/(?P<idp_name>[\w\.\-]+)/acs/', assertion_consumer_service, name='assertion_consumer_service'),
]


for provider in providers.registry.get_list():
    try:
        prov_mod = importlib.import_module(provider.get_package() + '.urls')
    except ImportError:
        logging.getLogger(__name__).warning(
            'url import failed for %s socialaccount provider' % provider.id,
            exc_info=True)
        continue
    prov_urlpatterns = getattr(prov_mod, 'urlpatterns', None)
    if prov_urlpatterns:
        urlpatterns += prov_urlpatterns
