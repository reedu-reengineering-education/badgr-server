# encoding: utf-8
from __future__ import unicode_literals

from django.core.management import BaseCommand
from django.db import connection

from badgeuser.models import CachedEmailAddress, UserRecipientIdentifier
from issuer.models import BadgeInstance


class Command(BaseCommand):
    def __init__(self):
        super(Command, self).__init__()
        self.cursor = connection.cursor()

    def handle(self, *args, **options):

        self.stdout.write("Updating BadgeInstaces...")
        self.stdout.write("1. Setting users from verified CachedEmailAddress")
        for verified_id in CachedEmailAddress.objects.filter(verified=True):
            self.update(verified_id.user, verified_id.email)
        
        self.stdout.write("2. Setting users from verified UserRecipientIdentifier")
        for verified_id in UserRecipientIdentifier.objects.filter(verified=True):
            self.update(verified_id.user, verified_id.identifier)

        # Trigger cache updates
        self.stdout.write("3. Triggering cache updates")
        for b in BadgeInstance.objects.filter(user__isnull=False):
            b.publish()

        self.stdout.write("All done.")

    def update(self, user, identifier):
        BadgeInstance.objects.filter(recipient_identifier=identifier).update(user=user)