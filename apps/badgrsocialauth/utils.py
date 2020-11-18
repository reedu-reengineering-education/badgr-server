import urllib

from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
from rest_framework.authentication import TokenAuthentication

from mainsite.models import BadgrApp
from mainsite.utils import list_of


def get_session_verification_email(request):
    return request.session.get('verification_email', None)


def set_session_verification_email(request, verification_email):
    request.session['verification_email'] = verification_email


def get_session_badgr_app(request):
    """
    This method can ONLY be used within the SSO process. The badgr_app_pk value
    in request.session is ONLY stored prior to the external hop to the SSO.
    All usages should expressly handle None return case.
    """
    try:
        if request and hasattr(request, 'session'):
            return BadgrApp.objects.get(pk=request.session.get('badgr_app_pk', -1))
    except BadgrApp.DoesNotExist:
        return None


def set_session_badgr_app(request, badgr_app):
    request.session['badgr_app_pk'] = badgr_app.pk


def get_session_authcode(request):
    if request is not None:
        return request.session.get('badgr_authcode', None)


def set_session_authcode(request, authcode):
    request.session['badgr_authcode'] = authcode


def get_verified_user(auth_token):
    authenticator = TokenAuthentication()
    verified_user, _ = authenticator.authenticate_credentials(auth_token)
    return verified_user


def redirect_to_frontend_error_toast(request, message):
    badgr_app = BadgrApp.objects.get_current(request)
    redirect_url = "{url}?authError={message}".format(
        url=badgr_app.ui_login_redirect,
        message=urllib.parse.quote(message))
    return HttpResponseRedirect(redirect_to=redirect_url)


def generate_provider_identifier(sociallogin=None, socialaccount=None):
    if socialaccount is None:
        socialaccount = sociallogin.account
    if socialaccount.provider == 'twitter':
        return 'https://twitter.com/{}'.format(socialaccount.extra_data['screen_name'].lower())


def userdata_from_saml_assertion(claims, data_field='email', config=None):
    """
    From a set of SAML claims processed into a dict, extract a claim for the desired property based
    on system settings and the specific Saml2Config, if that claim exists. Raise ValidationError if missing
    :param claims: dict
    :param data_field: str ('email', 'first_name', 'last_name')
    :param config: Saml2Configuration
    :return: str
    """
    config_settings = config.custom_settings_data
    configured_keys = {
        'email': set(settings.SAML_EMAIL_KEYS) | set(config_settings.get('email', [])),
        'first_name': set(settings.SAML_FIRST_NAME_KEYS) | set(config_settings.get('first_name', [])),
        'last_name': set(settings.SAML_LAST_NAME_KEYS) | set(config_settings.get('last_name', []))
    }

    if len(configured_keys[data_field] & set(claims.keys())) == 0:
        raise ValidationError('Missing {} in SAML assertions, received {}'.format(data_field, list(claims.keys())))

    return [list_of(claims[key])[0] for key in configured_keys[data_field] if key in claims][0]
