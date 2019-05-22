from allauth.socialaccount.providers.facebook.provider import FacebookProvider
from allauth.socialaccount.providers.linkedin_oauth2.provider import LinkedInOAuth2Provider
from allauth.tests import MockedResponse
from django.core import mail

from .base import BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase


class SendsVerificationEmailMixin(object):
    def test_verification_email(self):
        # Expect this provider to send a verification email on first login
        before_count = len(mail.outbox)
        response = self.login(self.get_mocked_response())
        self.assertEqual(response.status_code, 302)  # sanity
        self.assertEqual(len(mail.outbox), before_count + 1)


class FacebookProviderTests(SendsVerificationEmailMixin, BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase):
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


class LinkedInOAuth2ProviderTests(SendsVerificationEmailMixin, BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase):
    provider_id = LinkedInOAuth2Provider.id

    def get_mocked_response(self):
        return MockedResponse(200, """
        {
          "emailAddress": "raymond.penners@intenct.nl",
          "firstName": "Raymond",
          "id": "ZLARGMFT1M",
          "lastName": "Penners",
          "pictureUrl": "http://m.c.lnkd.licdn.com/mpr/mprx/0_e0hbvSLc",
          "publicProfileUrl": "http://www.linkedin.com/in/intenct"
        }""")
