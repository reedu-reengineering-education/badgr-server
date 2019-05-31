# encoding: utf-8
from __future__ import unicode_literals

from django.core.urlresolvers import reverse
from mainsite.tests import SetupIssuerHelper, BadgrTestCase


class AssertionFetching(SetupIssuerHelper, BadgrTestCase):

    def test_can_fetch_assertions_by_recipient_ids(self):
        user1 = self.setup_user(authenticate=True, email='user1@example.com')
        user2 = self.setup_user(email='user2@example.com')
        user3 = self.setup_user(email='user3@example.com')
        issuer = self.setup_issuer(owner=user1)
        badgeclass = self.setup_badgeclass(issuer=issuer)

        badgeclass.issue(recipient_id=user1.email)
        badgeclass.issue(recipient_id=user2.email)
        badgeclass.issue(recipient_id=user3.email)

        # Test default case without any filtering
        url = "{url}".format(
            url=reverse('v2_api_issuer_assertion_list', kwargs={'entity_id': issuer.entity_id}),
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 3)
        
        # Filter for 1 recipient
        url = "{url}?recipient={email2}".format(
            url=reverse('v2_api_issuer_assertion_list', kwargs={'entity_id': issuer.entity_id}),
            email2=user2.email
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 1)
        
        # Filter for 2 recipient
        url = "{url}?recipient={email2}&recipient={email3}".format(
            url=reverse('v2_api_issuer_assertion_list', kwargs={'entity_id': issuer.entity_id}),
            email2=user2.email,
            email3=user3.email
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 2)

        
