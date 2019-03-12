from .base import BaseBadgrEvent


class BlacklistEarnerNotNotifiedEvent(BaseBadgrEvent):
    def __init__(self, badge_instance):
        self.badge_instance = badge_instance

    def to_representation(self):
        return {
            'recipient_identifier': self.badge_instance.recipient_identifier,
            'badge_instance': self.badge_instance.json,
        }


class BlacklistAssertionNotCreatedEvent(BaseBadgrEvent):
    def __init__(self, badge_instance):
        self.badge_instance = badge_instance

    def to_representation(self):
        return {
            'recipient_identifier': self.badge_instance.recipient_identifier,
            'badge_instance': self.badge_instance.json,
        }


class BlacklistUnsubscribeInvalidLinkEvent(BaseBadgrEvent):
    def __init__(self, email):
        self.email = email

    def to_representation(self):
        return {
            'email': self.email
        }


class BlacklistUnsubscribeRequestSuccessEvent(BaseBadgrEvent):
    def __init__(self, email):
        self.email = email

    def to_representation(self):
        return {
            'email': self.email
        }


class BlacklistUnsubscribeRequestFailedEvent(BaseBadgrEvent):
    def __init__(self, email):
        self.email = email

    def to_representation(self):
        return {
            'email': self.email
        }
