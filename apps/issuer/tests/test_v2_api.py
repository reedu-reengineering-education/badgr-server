# encoding: utf-8
from __future__ import unicode_literals

from django.core.urlresolvers import reverse
from mainsite.tests import SetupIssuerHelper, BadgrTestCase
from mainsite.models import ApplicationInfo, AccessTokenProxy
from oauth2_provider.models import Application, AccessToken
from django.utils import timezone
from datetime import timedelta


class AssertionsChangedSince(SetupIssuerHelper, BadgrTestCase):
    def test_application_can_fetch_changed_assertions(self):
        staff = self.setup_user(email='staff@example.com')
        recipient = self.setup_user(email='recipient@example.com')

        issuer = self.setup_issuer(owner=staff)
        badgeclass = self.setup_badgeclass(issuer=issuer)
        badgeclass.issue(recipient_id=recipient.email)
        badgeclass.issue(recipient_id=staff.email)
        url = reverse('v2_api_assertions_changed_list')

        clientApp = self.setup_user(email='clientApp@example.com', token_scope='r:assertions')
        app = Application.objects.create(
            client_id='clientApp-authcode', client_secret='testsecret', authorization_grant_type='authorization-code',
            user=clientApp)
        AccessToken.objects.create(
            user=staff, scope='rw:issuer r:profile r:backpack', expires=timezone.now() + timedelta(hours=1),
            token='123', application=app
        )
        AccessToken.objects.create(
            user=recipient, scope='rw:issuer r:profile r:backpack', expires=timezone.now() + timedelta(hours=1),
            token='abc', application=app
        )

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 2)

    def test_user_cant_fetch_changed_assertions(self):
        staff = self.setup_user(email='staff@example.com')
        recipient = self.setup_user(email='recipient@example.com', authenticate=True)

        issuer = self.setup_issuer(owner=staff)
        badgeclass = self.setup_badgeclass(issuer=issuer)
        badgeclass.issue(recipient_id=recipient.email)
        badgeclass.issue(recipient_id=staff.email)
        url = reverse('v2_api_assertions_changed_list')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)


class AssertionFetching(SetupIssuerHelper, BadgrTestCase):
    def test_can_paginate_fetch_assertions_by_recipient(self):
        user1 = self.setup_user(authenticate=True, email='user1@example.com')
        user2 = self.setup_user(email='user2@example.com')
        user3 = self.setup_user(email='user3@example.com')
        issuer = self.setup_issuer(owner=user1)
        badgeclass = self.setup_badgeclass(issuer=issuer)

        badgeclass.issue(recipient_id=user1.email)
        badgeclass.issue(recipient_id=user2.email)
        badgeclass.issue(recipient_id=user3.email)

        url = "{url}?num=2&recipient={email3}".format(
            url=reverse('v2_api_badgeclass_assertion_list',
                        kwargs={'entity_id': badgeclass.entity_id}),
            email3=user3.email
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 1)

    def test_can_fetch_assertions_by_recipient_ids_for_badgeclass(self):
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
            url=reverse('v2_api_badgeclass_assertion_list', kwargs={'entity_id': badgeclass.entity_id}),
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 3)

        # Filter for 1 recipient
        url = "{url}?recipient={email2}".format(
            url=reverse('v2_api_badgeclass_assertion_list', kwargs={'entity_id': badgeclass.entity_id}),
            email2=user2.email
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 1)

        # Filter for 2 recipient
        url = "{url}?recipient={email2}&recipient={email3}".format(
            url=reverse('v2_api_badgeclass_assertion_list', kwargs={'entity_id': badgeclass.entity_id}),
            email2=user2.email,
            email3=user3.email
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 2)

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
