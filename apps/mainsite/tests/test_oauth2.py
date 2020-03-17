import base64
import urllib.request, urllib.parse, urllib.error

from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import Application

from badgeuser.authcode import encrypt_authcode, decrypt_authcode, authcode_for_accesstoken
from mainsite.models import AccessTokenProxy
from issuer.models import Issuer
from mainsite.models import ApplicationInfo
from mainsite.tests import BadgrTestCase, SetupIssuerHelper
from mainsite.utils import backoff_cache_key


class OAuth2TokenTests(SetupIssuerHelper, BadgrTestCase):
    def setUp(self):
        cache.clear()
        super(OAuth2TokenTests, self).setUp()

    def test_client_credentials_can_get_token(self):
        client_id = "test"
        client_secret = "secret"
        client_user = self.setup_user(authenticate=False)
        application = Application.objects.create(
            client_id=client_id,
            client_secret=client_secret,
            user=client_user,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            name='test client app'
        )
        ApplicationInfo.objects.create(
            application=application,
            allowed_scopes='rw:issuer'
        )

        request_data = dict(
            grant_type='client_credentials',
            client_id=application.client_id,
            client_secret=client_secret,
            scope='rw:issuer'
        )
        response = self.client.post(reverse('oauth2_provider_token'), data=request_data)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(reverse('oauth2_provider_token'), data=request_data)
        self.assertEqual(response.status_code, 200)

    def test_can_rw_issuer_with_token(self):
        client_id = "test"
        client_secret = "secret"
        client_user = self.setup_user(authenticate=False)
        application = Application.objects.create(
            client_id=client_id,
            client_secret=client_secret,
            user=client_user,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            name='test client app'
        )
        ApplicationInfo.objects.create(
            application=application,
            allowed_scopes='rw:issuer'
        )

        request_data = dict(
            grant_type='client_credentials',
            client_id=application.client_id,
            client_secret=client_secret,
            scope='rw:issuer'
        )
        response = self.client.post(reverse('oauth2_provider_token'), data=request_data)
        self.assertEqual(response.status_code, 200)
        first_token = response.json()['access_token']
        first_token_instance = AccessTokenProxy.objects.get(token=first_token)

        # Do it again... The token should update its "token" value.
        response = self.client.post(reverse('oauth2_provider_token'), data=request_data)
        self.assertEqual(response.status_code, 200)

        token = response.json()['access_token']
        new_token_instance = AccessTokenProxy.objects.get(token=token)
        # self.assertEqual(first_token_instance.pk, new_token_instance.pk)

        self.client.credentials(HTTP_AUTHORIZATION='Bearer {}'.format(token))
        response = self.client.post(
            reverse('v2_api_issuer_list'),
            data={'name': 'Another Issuer', 'url': 'http://a.com/b', 'email': client_user.email}
        )
        self.assertEqual(response.status_code, 201)

        new_token_instance.expires = timezone.now() - timezone.timedelta(days=1)
        new_token_instance.save()
        response = self.client.get(reverse('v2_api_issuer_list'))
        self.assertEqual(response.status_code, 401)

    def test_can_encrypt_decrypt_authcode(self):
        payload = "fakeentityid"
        code = encrypt_authcode(payload)
        decrypted_payload = decrypt_authcode(code)
        self.assertEqual(payload, decrypted_payload)

    def test_can_use_authcode_exchange(self):
        user = self.setup_user(authenticate=True)
        application = Application.objects.create(
            client_id='testing-authcode',
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD
        )
        ApplicationInfo.objects.create(application=application)
        accesstoken = AccessTokenProxy.objects.generate_new_token_for_user(user, application=application, scope='r:profile')

        # can exchange valid authcode for accesstoken
        authcode = authcode_for_accesstoken(accesstoken)
        response = self.client.post(reverse('oauth2_code_exchange'), dict(code=authcode))
        self.assertEqual(response.status_code, 200)
        self.assertDictContainsSubset({'access_token': accesstoken.token}, response.data)

        # cant exchange invalid authcode
        response = self.client.post(reverse('oauth2_code_exchange'), dict(code="InvalidAuthCode"))
        self.assertEqual(response.status_code, 400)

        # cant exchange expired authcode
        expired_authcode = authcode_for_accesstoken(accesstoken, expires_seconds=0)
        response = self.client.post(reverse('oauth2_code_exchange'), dict(code=expired_authcode))
        self.assertEqual(response.status_code, 400)

    def _base64_data_uri_encode(self, file, mime):
        encoded = base64.b64encode(file.read())
        return "data:{};base64,{}".format(mime, encoded)

    def test_can_use_authcode_exchange_refresh(self):
        user = self.setup_user(authenticate=False)
        issuer = self.setup_issuer(owner=user)
        application = Application.objects.create(
            client_id='testing-authcode',
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE
        )
        ApplicationInfo.objects.create(application=application)
        accesstoken = AccessTokenProxy.objects.generate_new_token_for_user(
            user, application=application, scope='r:profile', refresh_token=True
        )

        self.client.credentials(HTTP_AUTHORIZATION='Bearer {}'.format(accesstoken.token))
        response = self.client.get('/v2/users/self')
        self.assertEqual(response.status_code, 200)
        accesstoken.expires = timezone.datetime.now() - timezone.timedelta(hours=1)
        accesstoken.save()

        response = self.client.get('/v2/users/self')
        self.assertEqual(response.status_code, 401)

        refresh_token = accesstoken.refresh_token.token
        post_data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': application.client_id,
            'client_secret': application.client_secret
        }
        response = self.client.post('/o/token', data=post_data)
        self.assertEqual(response.status_code, 200)
        new_access_token = response.json()['access_token']
        self.client.credentials(HTTP_AUTHORIZATION='Bearer {}'.format(new_access_token))

        response = self.client.get('/v2/users/self')
        self.assertEqual(response.status_code, 200)

        new_token = AccessTokenProxy.objects.get(token=new_access_token)
        new_token.expires = accesstoken.expires
        new_token.save()

        response = self.client.get('/v2/users/self')
        self.assertEqual(response.status_code, 401)

        with open(self.get_test_image_path(), 'rb') as badge_image:
            badgeclass_data = {
                    'name': 'Badge of Slugs',
                    'description': "Recognizes slimy learners with a penchant for lettuce",
                    'image': self._base64_data_uri_encode(badge_image, 'image/png'),
                    'criteriaNarrative': 'Eat lettuce. Grow big.'
                }
        response = self.client.post('/v2/badgeclasses', badgeclass_data)
        self.assertEqual(response.status_code, 401)

    @override_settings(TOKEN_BACKOFF_MAXIMUM_SECONDS=3600, TOKEN_BACKOFF_PERIOD_SECONDS=2)
    def test_can_reset_failed_login_backoff(self):
        cache.clear()
        password = 'secret'
        user = self.setup_user(authenticate=False, password=password, email='testemail233@example.test')
        backoff_key = backoff_cache_key(user.email, '127.0.0.1')
        application = Application.objects.create(
            client_id='public',
            client_secret='',
            user=None,
            authorization_grant_type=Application.GRANT_PASSWORD,
            name='public'
        )
        ApplicationInfo.objects.create(
            application=application,
            allowed_scopes='rw:issuer rw:backpack rw:profile'
        )

        post_data = {
            'username': user.email,
            'password': password
        }
        response = self.client.post('/o/token', data=post_data)
        self.assertEqual(response.status_code, 200)
        backoff_data = cache.get(backoff_key)
        self.assertIsNone(backoff_data)

        post_data['password'] = 'bad_and_incorrect'
        response = self.client.post('/o/token', data=post_data)
        self.assertEqual(response.status_code, 401)
        backoff_data = cache.get(backoff_key)
        self.assertEqual(backoff_data['count'], 1)
        backoff_time = backoff_data['until']

        post_data['password'] = password
        response = self.client.post('/o/token', data=post_data)
        self.assertEqual(response.status_code, 429)
        backoff_data = cache.get(backoff_key)
        self.assertEqual(backoff_data['count'], 2, "Count increases even if sent too soon even if password is right")
        self.assertGreaterEqual(backoff_data['until'], backoff_time + timezone.timedelta(seconds=2),
                                "backoff time should increase by at least two seconds")

        backoff_data['until'] = backoff_time - timezone.timedelta(seconds=3)  # reset to a time in the past
        cache.set(backoff_key, backoff_data)

        response = self.client.post('/o/token', data=post_data)
        self.assertEqual(response.status_code, 200)
        backoff_data = cache.get(backoff_key)
        self.assertIsNone(backoff_data)
