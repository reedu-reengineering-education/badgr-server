from mainsite.tests.base import BadgrTestCase
from mainsite.utils import clamped_backoff_in_seconds, iterate_backoff_count


class BackoffTests(BadgrTestCase):
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
            b = clamped_backoff_in_seconds(m)
            self.assertEqual(b, n, "For count {}, backoff should = {} seconds, not {}".format(m, n, b))

    def test_iterate_backoff_count(self):
        backoff = {
            'count': 1
        }

        new_backoff = iterate_backoff_count(backoff)
        self.assertEqual(new_backoff['count'], 2)