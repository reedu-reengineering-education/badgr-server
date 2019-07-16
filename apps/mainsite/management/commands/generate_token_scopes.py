from django.core.management.base import BaseCommand

from mainsite.models import AccessTokenProxy, AccessTokenScope


class Command(BaseCommand):
    def handle(self, *args, **options):
        self.stdout.write('Splitting all scopes on tokens')
        scopes = []
        for a in AccessTokenProxy.objects.all():
            for s in a.scope.split():
                scopes.append(AccessTokenScope(scope=s, token=a))

        self.stdout.write('Bulk creating AccessTokenScope')
        AccessTokenScope.objects.bulk_create(scopes)

        self.stdout.write('All done.')