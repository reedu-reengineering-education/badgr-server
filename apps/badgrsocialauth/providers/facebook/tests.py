from allauth.tests import MockedResponse

from badgrsocialauth.providers.tests.base import BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase
from badgrsocialauth.providers.tests.test_third_party import DoesNotSendVerificationEmailMixin

from .provider import VerifiedFacebookProvider


class VerifiedFacebookProviderTests(DoesNotSendVerificationEmailMixin, BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase):
    provider_id = VerifiedFacebookProvider.id

    def get_mocked_response(self):
        response = MockedResponse(200, """
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
        response.ok = True
        return response

    def test_can_add_facebook_account_to_profile(self):
        user = self.setup_user(token_scope="rw:profile")
        response = self.client.get('/v1/user/socialaccounts/connect?provider=facebook')
        self.assertEqual(response.status_code, 200)