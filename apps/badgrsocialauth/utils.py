import urllib
import urlparse

from django.http import HttpResponseRedirect

from rest_framework.response import Response
from rest_framework.status import HTTP_500_INTERNAL_SERVER_ERROR
from rest_framework.authentication import TokenAuthentication

from mainsite.models import BadgrApp


def set_url_query_params(url, **kwargs):
    """
    Given a url, possibly including query parameters, return a url with the given query parameters set, replaced on a
    per-key basis.
    """
    url_parts = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(kwargs)
    url_parts[4] = urllib.urlencode(query)
    return urlparse.urlunparse(url_parts)


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
        message=urllib.quote(message))
    return HttpResponseRedirect(redirect_to=redirect_url)
