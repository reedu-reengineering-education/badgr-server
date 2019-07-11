# encoding: utf-8
from __future__ import unicode_literals

from django.core.urlresolvers import reverse
from django.test import override_settings

from mainsite.tests import SetupIssuerHelper, BadgrTestCase
from mainsite.models import AccessTokenProxy
from oauth2_provider.models import Application
from django.utils import timezone
from datetime import timedelta
from badgeuser.models import UserRecipientIdentifier


@override_settings(
    CELERY_ALWAYS_EAGER=True
)
class AssertionsChangedSince(SetupIssuerHelper, BadgrTestCase):
    def test_user_cant_fetch_changed_assertions(self):
        staff = self.setup_user(email='staff@example.com')
        recipient = self.setup_user(email='recipient@example.com', authenticate=True)

        issuer = self.setup_issuer(owner=staff)
        badgeclass = self.setup_badgeclass(issuer=self.issuer)
        badgeclass.issue(recipient_id=recipient.email)
        badgeclass.issue(recipient_id=staff.email)
        url = reverse('v2_api_assertions_changed_list')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_application_can_fetch_changed_assertions(self):
        staff = self.setup_user(email='staff@example.com')
        recipient = self.setup_user(email='recipient@example.com', authenticate=False)
        unrelated_recipient = self.setup_user(email='otherrecipient1@example.com')

        issuer = self.setup_issuer(owner=staff)
        badgeclass = self.setup_badgeclass(issuer=issuer)
        badgeclass.issue(recipient_id=recipient.email)
        badgeclass.issue(recipient_id=staff.email)
        badgeclass.issue(recipient_id=unrelated_recipient.email)
        url = reverse('v2_api_assertions_changed_list')

        clientAppUser = self.setup_user(email='clientApp@example.com', token_scope='r:assertions')
        app = Application.objects.create(
            client_id='clientApp-authcode', client_secret='testsecret', authorization_grant_type='authorization-code',
            user=clientAppUser)
        AccessTokenProxy.objects.create(
            user=staff, scope='rw:issuer r:profile r:backpack', expires=timezone.now() + timedelta(hours=1),
            token='123', application=app
        )
        AccessTokenProxy.objects.create(
            user=recipient, scope='rw:issuer r:profile r:backpack', expires=timezone.now() + timedelta(hours=1),
            token='abc2', application=app
        )

        unrelated_app = Application.objects.create(
            client_id='clientApp-authcode-2', client_secret='testsecret', authorization_grant_type='authorization-code',
            user=None)
        AccessTokenProxy.objects.create(
            user=unrelated_recipient, scope='rw:issuer r:profile r:backpack', expires=timezone.now() + timedelta(hours=1),
            token='abc3', application=unrelated_app
        )

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 2)


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

    def test_can_fetch_assertions_by_url_based_recipient_ids(self):
        url_recipient = "http://example.com"
        u1 = self.setup_user(authenticate=True, email="hey@example.com")
        UserRecipientIdentifier.objects.create(identifier=url_recipient, user=u1)
        UserRecipientIdentifier.objects.create(identifier="http://example.com/notme", user=u1)
        i = self.setup_issuer(owner=u1)
        b = self.setup_badgeclass(issuer=i)
        b.issue(recipient_id=url_recipient)
        b.issue(recipient_id=u1.email)
        b.issue(recipient_id="http://example.com/notme")
        url = "{url}?recipient={url_recipient}".format(
            url=reverse('v2_api_badgeclass_assertion_list', kwargs={'entity_id': b.entity_id}),
            url_recipient=url_recipient
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['result']), 1)


