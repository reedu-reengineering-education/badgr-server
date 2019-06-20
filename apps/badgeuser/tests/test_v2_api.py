from django.core.urlresolvers import reverse
from mainsite.tests import BadgrTestCase

class AccessTokenHandling(BadgrTestCase):
    def test_token_deletion(self):
        pass
        # self.setup_user(email='staff@example.com', authenticate=True)
        # url = reverse('v2_api_access_token_detail')
        # url = reverse('v2_api_access_token_list')
        # response = self.client.get(url)
        # self.assertEqual(response.status_code, 200)
        #
        # self.assertEqual(len(response.data['result']), 2)