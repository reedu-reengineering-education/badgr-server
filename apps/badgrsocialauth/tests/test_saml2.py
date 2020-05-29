import base64

import os
from urlparse import urlparse, parse_qs

from django.shortcuts import reverse
from django.test import override_settings
from django.test.client import RequestFactory

from badgrsocialauth.models import Saml2Configuration, Saml2Account
from badgrsocialauth.views import auto_provision, saml2_client_for
from badgrsocialauth.utils import set_session_authcode

from badgeuser.models import CachedEmailAddress, BadgeUser

from mainsite.models import AccessTokenProxy, BadgrApp
from mainsite.tests import BadgrTestCase, SetupUserHelper
from mainsite import TOP_DIR

class SAML2Tests(BadgrTestCase):
    def setUp(self):
        super(SAML2Tests, self).setUp()
        self.test_files_path = os.path.join(TOP_DIR, 'apps', 'badgrsocialauth', 'testfiles')
        self.badgr_sp_metadata_path = os.path.join(self.test_files_path, 'badgr-sp-metadata.txt')
        with open(self.badgr_sp_metadata_path, 'r') as f:
            metadata_xml = f.read()
        self.config = Saml2Configuration.objects.create(
            metadata_conf_url="http://example.com", slug="saml2.test", cached_metadata=metadata_xml
        )
        self.ipd_cert_path = os.path.join(self.test_files_path, 'idp-test-cert.pem')
        self.ipd_key_path = os.path.join(self.test_files_path, 'idp-test-key.pem')

        self.badgr_app = BadgrApp.objects.create(
            ui_login_redirect="https://example.com", ui_signup_failure_redirect='https://example.com/fail'
        )

    def create_signed_auth_request_saml2Configuration(self, idp_metadata):
        return Saml2Configuration.objects.create(
            metadata_conf_url="http://example.com",
            cached_metadata=idp_metadata,
            slug='saml2.authn',
            use_signed_authn_request=True
        )

    def test_signed_authn_request_option_creates_signed_metadata(self):
        with override_settings(
                SAML_KEY_FILE=self.ipd_key_path,
                SAML_CERT_FILE=self.ipd_cert_path):
            with open(self.badgr_sp_metadata_path, 'r') as f:
                idp_metadata = f.read()
                authn_request = self.create_signed_auth_request_saml2Configuration(idp_metadata)
                saml_client, config = saml2_client_for(authn_request.slug)
                self.assertTrue(saml_client.authn_requests_signed)
                self.assertNotEqual(saml_client.sec.sec_backend, None)

    def test_signed_authn_request_option_returns_self_posting_form_populated_with_signed_metadata(self):
        with override_settings(
                SAML_KEY_FILE=self.ipd_key_path,
                SAML_CERT_FILE=self.ipd_cert_path):
            with open(self.badgr_sp_metadata_path, 'r') as f:
                idp_metadata = f.read()
                authn_request = self.create_signed_auth_request_saml2Configuration(idp_metadata)
                url = '/account/sociallogin?provider=' + authn_request.slug
                redirect_url = '/account/saml2/' + authn_request.slug + '/'
                response = self.client.get(url, follow=True)
                intermediate_url, intermediate_url_status = response.redirect_chain[0]

                # login redirect to saml2 login
                self.assertEqual(intermediate_url, redirect_url)
                self.assertEqual(intermediate_url_status, 302)
                # self populated form generated with metadata file from self.ipd_metadata_path
                self.assertEqual(response.status_code, 200)
                # changing attribute location of element md:SingleSignOnService necessitates updating this value
                self.assertIsNot(
                    response.content.find('<form action="https://example.com/saml2/idp/SSOService.php" method="post">'), -1)
                self.assertIsNot(
                    response.content.find('<input type="hidden" name="SAMLRequest" value="'), -1)

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
        badgr_app = BadgrApp.objects.create(ui_login_redirect="example.com", cors='example.com')
        resp = auto_provision(None, email, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

    def test_login_with_unregistered_saml2_account(self):
        email = "test456@example.com"
        first_name = "firsty"
        last_name = "lastington"
        badgr_app = self.badgr_app
        resp = auto_provision(None, email, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

    def test_saml2_login_with_conflicts(self):
        email = "test8679@example.com"
        email2 = "test234425@example.com"
        first_name = "firsty"
        last_name = "lastington"
        idp_name = self.config.slug
        badgr_app = self.badgr_app

        # email does not exist
        resp = auto_provision(
            None, "different425@example.com", first_name, last_name, badgr_app, self.config, self.config.slug
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)
        self.assertEqual(Saml2Account.objects.all().count(), 1)
        email_address = CachedEmailAddress.objects.get(email='different425@example.com')
        self.assertTrue(email_address.verified)
        self.assertTrue(email_address.primary)

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
        email_address = CachedEmailAddress.objects.get(email=email)
        self.assertTrue(email_address.verified)
        self.assertTrue(email_address.primary)

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
        saml_account_count = Saml2Account.objects.count()
        resp = auto_provision(None, email2, first_name, last_name, badgr_app, self.config, self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authError", resp.url)
        self.assertIn(self.config.slug, resp.url)
        self.assertEqual(saml_account_count, Saml2Account.objects.count(), "A Saml2Account must not have been created.")

    def test_add_samlaccount_to_existing_user(self):
        # email exists, but is verified
        email = 'exampleuser@example.com'
        test_user = self.setup_user(
            email=email,
            token_scope='rw:profile rw:issuer rw:backpack'
        )

        preflight_response = self.client.get(
            reverse('v2_api_user_socialaccount_connect') + '?provider={}'.format(self.config.slug)
        )
        self.assertEqual(preflight_response.status_code, 200)
        location = urlparse(preflight_response.data['result']['url'])
        authcode = parse_qs(location.query)['authCode'][0]
        location = '?'.join([location.path, location.query])

        # the location now includes an auth code
        self.client.logout()
        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)
        location = response._headers['location'][1]

        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)

        # Can auto provision again
        rf = RequestFactory()
        fake_request = rf.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'saml_assertion': 'very fake'}
        )
        fake_request.session = dict()
        set_session_authcode(fake_request, authcode)

        resp = auto_provision(
            fake_request, email, test_user.first_name, test_user.last_name, self.badgr_app, self.config, self.config.slug
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)
        account = Saml2Account.objects.get(user=test_user)

    def get_idp_config(self, meta=None):
        from saml2 import BINDING_SOAP
        from saml2 import BINDING_HTTP_REDIRECT
        from saml2 import BINDING_HTTP_POST
        from saml2.saml import NAME_FORMAT_URI
        from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAME_FORMAT_BASIC

        from django.conf import settings

        metadata_sp_1 = os.path.join(self.test_files_path, 'metadata_sp_1.xml')
        metadata_sp_2 = os.path.join(self.test_files_path, 'metadata_sp_2.xml')
        vo_metadata = os.path.join(self.test_files_path, 'vo_metadata.xml')
        attribute_map_dir = os.path.join(self.test_files_path, 'attributemaps')

        BASE = "http://localhost:8088"

        local_metadata = {"local": [metadata_sp_1,metadata_sp_2,vo_metadata]}
        metadata_source = local_metadata if meta is None else {'inline': [meta]}

        return {
            "entityid": "urn:mace:example.com:saml:roland:idp",
            "name": "Rolands IdP",
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [
                            ("%s/sso" % BASE, BINDING_HTTP_REDIRECT)],
                        "single_logout_service": [
                            ("%s/slo" % BASE, BINDING_SOAP),
                            ("%s/slop" % BASE, BINDING_HTTP_POST)]
                    },
                    "policy": {
                        "default": {
                            "lifetime": {"minutes": 15},
                            "attribute_restrictions": None,  # means all I have
                            "name_form": NAME_FORMAT_URI,
                        },
                        # "urn:mace:example.com:saml:roland:sp": {
                        "http://localhost:8000/account/saml2/saml2.authn/acs/": {
                            "lifetime": {"minutes": 5},
                            "nameid_format": NAMEID_FORMAT_PERSISTENT,
                        },
                        "https://example.com/sp": {
                            "lifetime": {"minutes": 5},
                            "nameid_format": NAMEID_FORMAT_PERSISTENT,
                            "name_form": NAME_FORMAT_BASIC
                        }
                    },
                    # "subject_data": full_path("subject_data.db"),
                    #"domain": "umu.se",
                    #"name_qualifier": ""
                },
            },
            "debug": 1,
            "key_file": self.ipd_key_path,
            "cert_file": self.ipd_cert_path,
            "xmlsec_binary": getattr(settings, 'XMLSEC_BINARY_PATH', None),
            "metadata": metadata_source,
            # "metadata": [{
            #     "class": "saml2.mdstore.MetaDataFile",
            #     "metadata": [metadata_sp_1,
            #                  metadata_sp_2,
            #                  vo_metadata],
            # }],
            "attribute_map_dir": attribute_map_dir,
            "organization": {
                "name": "Exempel AB",
                "display_name": [("Exempel AB", "se"), ("Example Co.", "en")],
                "url": "http://www.example.com/roland",
            },
            "contact_person": [
                {
                    "given_name": "John",
                    "sur_name": "Smith",
                    "email_address": ["john.smith@example.com"],
                    "contact_type": "technical",
                },
            ],
        }


    def test_acs_with_local_sp(self):
        from contextlib import closing
        from saml2.server import Server
        from saml2.authn_context import INTERNETPROTOCOLPASSWORD
        from saml2.metadata import create_metadata_string
        from badgrsocialauth.views import create_saml_config_for
        from saml2 import config
        from saml2.response import response_factory

        with override_settings(
                SAML_KEY_FILE=self.ipd_key_path,
                SAML_CERT_FILE=self.ipd_cert_path):

            with open(self.badgr_sp_metadata_path, 'r') as f:
                idp_metadata = f.read()
                saml2config = self.create_signed_auth_request_saml2Configuration(idp_metadata)
                sp_config = config.SPConfig()
                sp_config.load(create_saml_config_for(saml2config))

                metadata = create_metadata_string('', config=sp_config, sign=True)

        TIMESLACK = 60*5

        idp_config = self.get_idp_config(metadata)

        identity = {"eduPersonAffiliation": ["staff", "member"],
                    "surName": ["Jeter"], "givenName": ["Derek"],
                    "mail": ["foo@gmail.com"],
                    "title": ["shortstop"]}

        with closing(Server(idp_config)) as server:
            name_id = server.ident.transient_nameid(
                "urn:mace:example.com:saml:roland:idp", "id12")
            authn = {
                "class_ref": INTERNETPROTOCOLPASSWORD,
                "authn_auth": "http://www.example.com/login",
                "SubjectLocality": "172.31.50.90"
            }
            authn_response = server.create_authn_response(
                identity,
                "id12",  # in_response_to
                "http://lingon.catalogix.se:8087/",  # consumer_url
                "http://localhost:8000/account/saml2/saml2.authn/acs/",  # sp_entity_id
                name_id=name_id,
                sign_response=True,
                authn=authn
            )

            # resp = response_factory(
            #     authn_response, sp_config,
            #     return_addrs=['https://myreviewroom.com/saml2/acs/'],
            #     outstanding_queries={'id-f4d370f3d03650f3ec0da694e2348bfe':"http://localhost:8088/sso"},
            #     timeslack=TIMESLACK,
            #     # want_assertions_signed=True,
            #     decode=False
            # )

        # base64_encoded_response_metadata = base64.b64encode(authn_response)
        # base_64_utf8_response_metadata = base64_encoded_response_metadata.decode('utf-8')
        #
        # request = self.client.post(
        #     reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
        #     {'SAMLResponse': base_64_utf8_response_metadata}
        # )

        stop = ''

    def test_acs_with_attribute_response(self):
        from saml2.response import response_factory
        from saml2.response import StatusResponse
        from saml2.response import AuthnResponse
        from saml2 import config
        from badgrsocialauth.views import create_saml_config_for


        TIMESLACK = 60*5
        # using the SP sever config from saml test
        # server_conf_path = os.path.join(self.test_files_path, 'server_conf.py')
        # sp_config = config.SPConfig()
        # sp_config.load_file(server_conf_path)

        with open(self.badgr_sp_metadata_path, 'r') as f:
            idp_metadata = f.read()
            saml2config = self.create_signed_auth_request_saml2Configuration(idp_metadata)
            sp_config = config.SPConfig()
            sp_config.load(create_saml_config_for(saml2config))

        attribute_response_xml_path = os.path.join(self.test_files_path, 'attribute_response.xml')
        # now that I Have used the BAdgr config to create the SP meta data and passed that
        # data into the response factory can I do the same thing using the signed authn test above
        with open(attribute_response_xml_path) as fp:
            xml_response = fp.read()
        resp = response_factory(
            xml_response, sp_config,
            return_addrs=['https://myreviewroom.com/saml2/acs/'],
            outstanding_queries={'id-f4d370f3d03650f3ec0da694e2348bfe':"http://localhost:8088/sso"},
            timeslack=TIMESLACK,
            # want_assertions_signed=True,
            decode=False
        )
        # tests from the saml docs
        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, AuthnResponse)
        resp.sec.only_use_keys_in_metadata=False
        resp.parse_assertion()
        si = resp.session_info()
        assert si

        assertion = resp.xmlstr
        base64_encoded_metadata = base64.b64encode(assertion)
        base_64_utf8_metadata = base64_encoded_metadata.decode('utf-8')

        # request = self.client.post(
        #     reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
        #     {'SAMLResponse': base_64_utf8_metadata}
        # )
        stop = ''


    def test_add_samlaccount_to_existing_user_with_varying_email(self):
        email = 'exampleuser@example.com'
        t_user = self.setup_user(
            email=email,
            token_scope='rw:profile rw:issuer rw:backpack'
        )

        preflight_response = self.client.get(
            reverse('v2_api_user_socialaccount_connect') + '?provider={}'.format(self.config.slug)
        )
        self.assertEqual(preflight_response.status_code, 200)
        location = urlparse(preflight_response.data['result']['url'])
        authcode = parse_qs(location.query)['authCode'][0]
        location = '?'.join([location.path, location.query])

        # the location now includes an auth code
        self.client.logout()
        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)
        location = response._headers['location'][1]

        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)


        # Can auto provision again
        rf = RequestFactory()
        fake_request = rf.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'saml_assertion': 'very fake'}
        )
        fake_request.session = dict()
        set_session_authcode(fake_request, authcode)

        email2 = 'exampleuser_alt@example.com'
        resp = auto_provision(
            fake_request, email2, t_user.first_name, t_user.last_name, self.badgr_app, self.config, self.config.slug
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)
        Saml2Account.objects.get(user=t_user)  # There is a Saml account associated with the user.
        CachedEmailAddress.objects.get(email=email2, user=t_user, verified=True, primary=False)  # User has the email.
