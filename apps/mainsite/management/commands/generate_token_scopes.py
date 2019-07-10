from django.core.management.base import BaseCommand

from mainsite.models import AccessTokenProxy, AccessTokenScope


class Command(BaseCommand):
    def handle(self, *args, **options):
        for a in AccessTokenProxy.objects.all():
            for s in a.scope.split():
                AccessTokenScope.objects.create(scope=s, token=a)
