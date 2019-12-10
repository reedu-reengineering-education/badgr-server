from django.test import override_settings

from mainsite.tests.base import BadgrTestCase
from mainsite.utils import clamped_backoff_in_seconds, iterate_backoff_count

SETTINGS_OVERRIDE = {
    'TOKEN_BACKOFF_MAXIMUM_SECONDS': 3600,
    'TOKEN_BACKOFF_PERIOD_SECONDS': 2
}


class BackoffTests(BadgrTestCase):
    @override_settings(**SETTINGS_OVERRIDE)
    def test_clamped_backoff(self):
        for m, n in [
            (0, 1),
            (1, 2),
            (2, 4),
            (3, 8),
            (4, 16),
            (5, 32),
            (6, 64),
            (7, 128),
            (8, 256),
            (9, 512),
            (10, 1024),
            (11, 2048),
            (12, 3600),
            (13, 3600),
            (400, 3600),
        ]:
            backoff = clamped_backoff_in_seconds(m)
            self.assertEqual(backoff, n, "For count {}, backoff should = {} seconds, not {}".format(m, n, backoff))

    @override_settings(**SETTINGS_OVERRIDE)
    def test_iterate_backoff_count(self):
        backoff = {
            'count': 1
        }

        new_backoff = iterate_backoff_count(backoff)
        self.assertEqual(new_backoff['count'], 2)
