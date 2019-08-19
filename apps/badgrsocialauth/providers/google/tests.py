from allauth.tests import MockedResponse

from badgrsocialauth.providers.google.provider import UnverifiedGoogleProvider
from badgrsocialauth.providers.tests.base import BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase
from badgrsocialauth.providers.tests.test_third_party import SendsVerificationEmailMixin


class UnverifiedGoogleProviderTests(SendsVerificationEmailMixin, BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase):
    provider_id = UnverifiedGoogleProvider.id

    def get_mocked_response(self,
                            family_name='Penners',
                            given_name='Raymond',
                            name='Raymond Penners',
                            email="raymond.penners@example.com",
                            verified_email=True):
        return MockedResponse(200, """
              {"family_name": "%s", "name": "%s",
               "picture": "https://lh5.googleusercontent.com/photo.jpg",
               "locale": "nl", "gender": "male",
               "email": "%s",
               "link": "https://plus.google.com/108204268033311374519",
               "given_name": "%s", "id": "108204268033311374519",
               "verified_email": %s }
        """ % (family_name,
               name,
               email,
               given_name,
               (repr(verified_email).lower())))

    def test_can_add_google_account_to_profile(self):
        user = self.setup_user(token_scope="rw:profile")
        response = self.client.get('/v1/user/socialaccounts/connect?provider=google')
        self.assertEqual(response.status_code, 200)
