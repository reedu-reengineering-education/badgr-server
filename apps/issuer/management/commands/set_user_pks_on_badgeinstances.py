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

        for ce in CachedEmailAddress.objects.filter(verified=True):
            self.update({"user_pk": ce.user.pk, "identifier": ce.email})

        for rid in UserRecipientIdentifier.objects.filter(verified=True):
            self.update({"user_pk": rid.user.pk, "identifier": rid.identifier})

        # Trigger cache updates
        for b in BadgeInstance.objects.filter(user__isnull=False):
            b.publish()

        self.stdout.write("All done.")

    def update(self, kwargs):
        self.cursor.execute("""
            UPDATE issuer_badgeinstance 
            SET    user_id = {user_pk} 
            WHERE  recipient_identifier = "{identifier}"; 
        """.format(**kwargs))