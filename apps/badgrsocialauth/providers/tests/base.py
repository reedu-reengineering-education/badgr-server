from allauth.socialaccount.tests import OAuth2TestsMixin
from django.test import override_settings
from django.urls import reverse
from mainsite.tests import BadgrTestCase


class BadgrOAuth2TestsMixin(OAuth2TestsMixin):
    """
    Tests for OAuth2Provider subclasses in this application should use this
    mixin instead of OAuth2TestsMixin.

    Default tests include expectations broken by BadgrAccountAdapter, and
    this overrides those to make more sense.
    """
    def test_authentication_error(self):
        # override: base implementation looks for a particular template to be rendered.
        resp = self.client.get(reverse(self.provider.id + '_callback'))
        # Tried assertRedirects here, but don't want to couple this to the query params
        self.assertIn(self.badgr_app.ui_login_redirect, resp['Location'])

    def test_login(self):
        # override: base implementation uses assertRedirects, but we need to
        # allow for query params.
        response = self.login(self.get_mocked_response())
        self.assertEqual(response.status_code, 302)
        redirect_url, query_string = response.url.split('?')
        self.assertRegex(query_string, r'^authToken=[^\s]+$')
        self.assertEqual(redirect_url, self.badgr_app.ui_login_redirect)


@override_settings(UNSUBSCRIBE_SECRET_KEY='123a')
class BadgrSocialAuthTestCase(BadgrTestCase):
    def setUp(self):
        super(BadgrSocialAuthTestCase, self).setUp()
        self.badgr_app.ui_login_redirect = 'http://test-badgr.io/'
        self.badgr_app.save()

        session = self.client.session
        session.update({
            'badgr_app_pk': self.badgr_app.pk
        })
        session.save()
