from django.apps import AppConfig

from allauth.account.signals import user_signed_up, email_confirmed
from django.db.models.signals import post_save, pre_delete

from .signals import log_user_signed_up, log_email_confirmed, handle_email_created, delete_refresh_tokens


class BadgeUserConfig(AppConfig):
    name = 'badgeuser'

    def ready(self):
        user_signed_up.connect(log_user_signed_up,
                               dispatch_uid="user_signed_up")
        email_confirmed.connect(log_email_confirmed,
                                dispatch_uid="email_confirmed")

        from allauth.account.models import EmailAddress
        post_save.connect(handle_email_created,
                          sender=EmailAddress,
                          dispatch_uid="email_created")

        from oauth2_provider.models import RefreshToken  # , AccessToken
        from mainsite.models import AccessTokenProxy
        pre_delete.connect(delete_refresh_tokens(RefreshToken),
                           sender=AccessTokenProxy,
                           dispatch_uid="access_token_deleted")
