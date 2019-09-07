from urlparse import urlparse

from allauth.account.models import EmailAddress
from allauth.socialaccount import providers
from allauth.socialaccount.providers.twitter.provider import TwitterProvider, TwitterAccount
from django.core.exceptions import ValidationError

from badgeuser.models import UserRecipientIdentifier


class TwitterProviderWithIdentifier(TwitterProvider):
    id = 'twitter'
    name = 'Twitter'
    package = 'allauth.socialaccount.providers.twitter'
    account_class = TwitterAccount

    def sociallogin_from_response(self, request, response):
        sociallogin = super(TwitterProviderWithIdentifier, self).sociallogin_from_response(request, response)

        url = urlparse(sociallogin.account.get_profile_url())
        identifier = 'https://{}{}'.format(url.netloc, url.path.lower())

        user_identifier, created = UserRecipientIdentifier.objects.get_or_create(
            identifier=identifier, defaults=dict(verified=True, user=sociallogin.user))
        if created is False and user_identifier.user != sociallogin.user:
            raise ValidationError("This Twitter identifier is already associated with another account.")

        return sociallogin



providers.registry.register(TwitterProviderWithIdentifier)
