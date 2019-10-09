import json

from django.contrib.sites.models import Site

from badgeuser.models import CachedEmailAddress, BadgeUser
from mainsite.models import BadgrApp
from mainsite.tests import BadgrTestCase, SetupUserHelper
from allauth.socialaccount.models import SocialAccount, SocialApp

from badgrsocialauth.providers.twitter.tests import MOCK_TWITTER_PROFILE_RESPONSE


class SocialAccountV2APITests(BadgrTestCase, SetupUserHelper):
    def test_can_get_socialaccounts_list_view(self):
        site = Site.objects.first()
        user = self.setup_user(authenticate=True)
        socialapplication = SocialApp.objects.create(
            provider='twitter', name='Twitter OAuth2', client_id='fake', secret='also fake'
        )
        socialapplication.sites.add(site)
        socialaccount = SocialAccount.objects.create(
            user=user, provider='twitter', uid='123', extra_data=json.loads(MOCK_TWITTER_PROFILE_RESPONSE)
        )

        response = self.client.get('/v2/socialaccounts')
        self.assertEqual(response.status_code, 200)
        account_id = response.data.get('result')[0]['id']
        response = self.client.get('/v2/socialaccounts/{}'.format(account_id))
        self.assertEqual(response.status_code, 200)
        response = self.client.delete('/v2/socialaccounts/{}'.format(account_id))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(SocialAccount.objects.count(), 0)
