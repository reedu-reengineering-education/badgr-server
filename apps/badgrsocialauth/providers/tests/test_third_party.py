from allauth.socialaccount.providers.facebook.provider import FacebookProvider
from allauth.tests import MockedResponse
from django.core import mail

from .base import BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase


class FacebookProviderTests(BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase):
    provider_id = FacebookProvider.id

    def get_mocked_response(self):
        return MockedResponse(200, """
        {
           "id": "630595557",
           "name": "Raymond Penners",
           "first_name": "Raymond",
           "last_name": "Penners",
           "email": "raymond.penners@example.com",
           "link": "https://www.facebook.com/raymond.penners",
           "username": "raymond.penners",
           "birthday": "07/17/1973",
           "work": [
              {
                 "employer": {
                    "id": "204953799537777",
                    "name": "IntenCT"
                 }
              }
           ],
           "timezone": 1,
           "locale": "nl_NL",
           "verified": true,
           "updated_time": "2012-11-30T20:40:33+0000"
        }""")

    def test_verification_email(self):
        # Expect this provider to send a verification email on first login
        before_count = len(mail.outbox)
        response = self.login(self.get_mocked_response())
        self.assertEqual(response.status_code, 302)  # sanity
        self.assertEqual(len(mail.outbox), before_count + 1)
