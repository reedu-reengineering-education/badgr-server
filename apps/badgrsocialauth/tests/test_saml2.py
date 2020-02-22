from badgeuser.models import CachedEmailAddress, BadgeUser
from mainsite.models import BadgrApp
from mainsite.tests import BadgrTestCase

from badgrsocialauth.models import Saml2Configuration, Saml2Account
from badgrsocialauth.views import auto_provision, saml2_client_for


class SAML2Tests(BadgrTestCase):
    def setUp(self):
        super(SAML2Tests, self).setUp()
        self.config = Saml2Configuration.objects.create(metadata_conf_url="http://example.com", slug="saml2.test")

    def test_create_saml2_client(self):
        Saml2Configuration.objects.create(metadata_conf_url="http://example.com", cached_metadata="<xml></xml>",  slug="saml2.test2")
        client = saml2_client_for("saml2.test2")
        self.assertNotEqual(client, None)

    def test_oauth_to_saml2_redirection_flow(self):
        resp = self.client.get('/account/sociallogin?provider=' + self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/account/saml2/{}/'.format(self.config.slug))

    def test_login_with_registered_saml2_account(self):
        email = "test123@example.com"
        first_name = "firsty"
        last_name = "lastington"
        new_user = BadgeUser.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
        )
        # Auto verify emails
        email = CachedEmailAddress.objects.get(email=email)
        email.verified = True
        email.save()
        Saml2Account.objects.create(config=self.config, user=new_user, uuid=email)
        badgr_app = BadgrApp.objects.create(ui_login_redirect="example.com")
        resp = auto_provision(None, email, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

    def test_login_with_unregistered_saml2_account(self):
        email = "test456@example.com"
        first_name = "firsty"
        last_name = "lastington"
        badgr_app = BadgrApp.objects.create(ui_login_redirect="example.com")
        resp = auto_provision(None, email, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

    def test_saml2_login_with_conflicts(self):
        email = "test8679@example.com"
        email2 = "test234425@example.com"
        first_name = "firsty"
        last_name = "lastington"
        idp_name = self.config.slug
        badgr_app = BadgrApp.objects.create(
            ui_login_redirect="https://example.com", ui_signup_failure_redirect='https://example.com/fail'
        )

        # email does not exist
        resp = auto_provision(
            None, "different425@example.com", first_name, last_name, badgr_app, self.config, self.config.slug
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

        # email exists, but is unverified
        BadgeUser.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            send_confirmation=False
        )
        resp = auto_provision(None, email, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

        # Can auto provision again
        resp = auto_provision(None, email, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

        # email exists, but is verified
        BadgeUser.objects.create(
            email=email2,
            first_name=first_name,
            last_name=last_name,
            send_confirmation=False
        )
        cachedemail = CachedEmailAddress.objects.get(email=email2)
        cachedemail.verified = True
        cachedemail.save()
        resp = auto_provision(None, email2, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authError", resp.url)
        self.assertIn(self.config.slug, resp.url)
