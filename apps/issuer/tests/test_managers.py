# encoding: utf-8


from openbadges.verifier.openbadges_context import OPENBADGES_CONTEXT_V2_URI
import os
import responses

from backpack.tests.utils import CURRENT_DIRECTORY as BACKPACK_TESTS_DIRECTORY
from issuer.models import Issuer, BadgeClass, BadgeInstance, BadgeInstanceEvidence

from mainsite.tests import BadgrTestCase, SetupIssuerHelper


def _generate_issuer_obo(**kwargs):
    data = {
        '@context': OPENBADGES_CONTEXT_V2_URI,
        'id': 'https://example.com/issuer/1',
        'type': 'Issuer',
        'name': 'Basic Issuer',
        'url': 'http://a.com/issuer/website'
    }
    data.update(kwargs)
    return data


def _generate_badgeclass_ob2(**kwargs):
    data = {
        '@context': OPENBADGES_CONTEXT_V2_URI,
        'id': 'https://example.com/badgeclass/1',
        'type': 'BadgeClass',
        'name': 'Embedded badgeclass',
        'criteria': {
            'narrative': 'do it'
        },
        'image': 'http://example.com/badgeclass/1/image',
        'description': 'a beautiful bespoke badgeclass',
        'issuer': 'https://example.com/issuer/1'
    }
    data.update(kwargs)
    return data


def _generate_assertion_ob2(**kwargs):
    data = {
        '@context': OPENBADGES_CONTEXT_V2_URI,
        'id': 'https://example.com/assertion/1',
        'type': 'Assertion',
        'issuedOn': '2017-06-29T21:50:14+00:00',
        'recipient': {
            'type': 'email',
            'hashed': False,
            'identity': 'test@example.com'
        },
        'verification': {
            'type': 'HostedBadge'
        },
        'badge': 'https://example.com/badgeclass/1',
    }
    data.update(kwargs)
    return data


def _register_image_mock(url):
    responses.add(
        responses.GET, url,
        body=open(os.path.join(BACKPACK_TESTS_DIRECTORY, 'testfiles/unbaked_image.png'), 'rb').read(),
        status=200, content_type='image/png'
    )


class BadgeInstanceAndEvidenceManagerTests(SetupIssuerHelper, BadgrTestCase):
    def setUp(self):
        super(BadgeInstanceAndEvidenceManagerTests, self).setUp()
        self.local_owner_user = self.setup_user(authenticate=False)
        self.local_issuer = self.setup_issuer(owner=self.local_owner_user)
        random_unrelated_badgeclass = self.setup_badgeclass(issuer=self.local_issuer)

    @responses.activate
    def test_update_from_ob2_basic(self):
        recipient = self.setup_user(email='recipient1@example.org')

        issuer_ob2 = _generate_issuer_obo()
        badgeclass_ob2 = _generate_badgeclass_ob2()
        assertion_ob2 = _generate_assertion_ob2()
        _register_image_mock(badgeclass_ob2['image'])

        issuer, _ = Issuer.objects.get_or_create_from_ob2(issuer_ob2)
        badgeclass, _ = BadgeClass.objects.get_or_create_from_ob2(issuer, badgeclass_ob2)
        badgeinstance, _ = BadgeInstance.objects.get_or_create_from_ob2(
            badgeclass, assertion_ob2, recipient_identifier='test@example.com'
        )
        self.assertTrue(badgeinstance.badgeclass, badgeclass)

        # Add evidence item that didn't exist at initial import
        assertion_ob2['evidence'] = {'id': 'https://example.com/evidence/1'}
        updated, _ = BadgeInstance.objects.update_from_ob2(
            badgeclass, assertion_ob2, recipient_identifier=badgeinstance.recipient_identifier
        )
        self.assertEqual(updated.pk, badgeinstance.pk)
        self.assertEqual(BadgeInstanceEvidence.objects.count(), 1)
        self.assertEqual(updated.cached_evidence().count(), 1)

        # That evidence item has now been deleted, make sure we stay up to date there.
        del assertion_ob2['evidence']
        updated, _ = BadgeInstance.objects.update_from_ob2(
            badgeclass, assertion_ob2, recipient_identifier=badgeinstance.recipient_identifier
        )
        self.assertEqual(BadgeInstanceEvidence.objects.count(), 0)

        # An evidence url gets added as a string in Open Badges 1.x style
        assertion_ob2['evidence'] = 'https://example.com/evidence/2'
        updated, _ = BadgeInstance.objects.update_from_ob2(
            badgeclass, assertion_ob2, recipient_identifier=badgeinstance.recipient_identifier
        )
        self.assertEqual(BadgeInstanceEvidence.objects.count(), 1)
        evidence_item = BadgeInstanceEvidence.objects.first()
        self.assertEqual(evidence_item.badgeinstance_id, badgeinstance.pk)
        self.assertEqual(evidence_item.evidence_url, assertion_ob2['evidence'])
        self.assertIsNone(evidence_item.narrative)

