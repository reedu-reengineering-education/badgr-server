from allauth.socialaccount.providers.azure.provider import AzureProvider
from allauth.socialaccount.providers.facebook.provider import FacebookProvider
from allauth.socialaccount.providers.linkedin_oauth2.provider import LinkedInOAuth2Provider
from allauth.tests import MockedResponse

from .base import BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase, SendsVerificationEmailMixin


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


class AzureProviderTests(SendsVerificationEmailMixin, BadgrOAuth2TestsMixin, BadgrSocialAuthTestCase):
    provider_id = AzureProvider.id

    def get_mocked_response(self):
        return MockedResponse(200, """
        {"displayName": "John Smith", "mobilePhone": null,
        "preferredLanguage": "en-US", "jobTitle": "Director",
        "userPrincipalName": "john@smith.com",
        "@odata.context":
        "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
        "officeLocation": "Paris", "businessPhones": [],
        "mail": "john@smith.com", "surname": "Smith",
        "givenName": "John", "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        """)
