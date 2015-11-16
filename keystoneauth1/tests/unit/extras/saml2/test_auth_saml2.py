#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid

from lxml import etree

from keystoneauth1 import exceptions
from keystoneauth1.extras import _saml2 as saml2
from keystoneauth1.tests.unit.extras.saml2 import fixtures as saml2_fixtures
from keystoneauth1.tests.unit.extras.saml2 import utils
from keystoneauth1.tests.unit import matchers


class AuthenticateviaSAML2Tests(utils.TestCase):

    GROUP = 'auth'
    TEST_TOKEN = uuid.uuid4().hex

    def setUp(self):
        super(AuthenticateviaSAML2Tests, self).setUp()

        self.ECP_SP_EMPTY_REQUEST_HEADERS = {
            'Accept': 'text/html; application/vnd.paos+xml',
            'PAOS': ('ver="urn:liberty:paos:2003-08";'
                     '"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"')
        }

        self.ECP_SP_SAML2_REQUEST_HEADERS = {
            'Content-Type': 'application/vnd.paos+xml'
        }

        self.ECP_SAML2_NAMESPACES = {
            'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
            'S': 'http://schemas.xmlsoap.org/soap/envelope/',
            'paos': 'urn:liberty:paos:2003-08'
        }
        self.ECP_RELAY_STATE = '//ecp:RelayState'
        self.ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:'
                                                  'Request/'
                                                  '@responseConsumerURL')
        self.ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                                     '@AssertionConsumerServiceURL')

        self.IDENTITY_PROVIDER = 'testidp'
        self.IDENTITY_PROVIDER_URL = 'http://local.url'
        self.PROTOCOL = 'saml2'
        self.FEDERATION_AUTH_URL = '%s/%s' % (
            self.TEST_URL,
            'OS-FEDERATION/identity_providers/testidp/protocols/saml2/auth')
        self.SHIB_CONSUMER_URL = ('https://openstack4.local/'
                                  'Shibboleth.sso/SAML2/ECP')

        self.saml2plugin = saml2.V3Saml2Password(
            self.TEST_URL,
            self.IDENTITY_PROVIDER, self.IDENTITY_PROVIDER_URL,
            self.TEST_USER, self.TEST_TOKEN, self.PROTOCOL)

    def test_initial_sp_call(self):
        """Test initial call, expect SOAP message."""
        self.requests_mock.get(
            self.FEDERATION_AUTH_URL,
            content=utils.make_oneline(saml2_fixtures.SP_SOAP_RESPONSE))
        a = self.saml2plugin._send_service_provider_request(self.session)

        self.assertFalse(a)

        sp_soap_response = etree.tostring(self.saml2plugin.saml2_authn_request)

        self.assertThat(saml2_fixtures.SP_SOAP_RESPONSE,
                        matchers.XMLEquals(sp_soap_response))

        self.assertEqual(
            self.saml2plugin.sp_response_consumer_url, self.SHIB_CONSUMER_URL,
            "Expected consumer_url set to %s instead of %s" % (
                self.SHIB_CONSUMER_URL,
                str(self.saml2plugin.sp_response_consumer_url)))

    def test_initial_sp_call_when_saml_authenticated(self):
        self.requests_mock.get(
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        a = self.saml2plugin._send_service_provider_request(self.session)
        self.assertTrue(a)
        self.assertEqual(
            saml2_fixtures.UNSCOPED_TOKEN['token'],
            self.saml2plugin.authenticated_response.json()['token'])
        self.assertEqual(
            saml2_fixtures.UNSCOPED_TOKEN_HEADER,
            self.saml2plugin.authenticated_response.headers['X-Subject-Token'])

    def test_get_unscoped_token_when_authenticated(self):
        self.requests_mock.get(
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                     'Content-Type': 'application/json'})

        token = self.saml2plugin.get_auth_ref(self.session)

        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                         token.auth_token)

    def test_initial_sp_call_invalid_response(self):
        """Send initial SP HTTP request and receive wrong server response."""
        self.requests_mock.get(self.FEDERATION_AUTH_URL,
                               text='NON XML RESPONSE')

        self.assertRaises(
            exceptions.AuthorizationFailure,
            self.saml2plugin._send_service_provider_request,
            self.session)

    def test_send_authn_req_to_idp(self):
        self.requests_mock.post(self.IDENTITY_PROVIDER_URL,
                                content=saml2_fixtures.SAML2_ASSERTION)

        self.saml2plugin.sp_response_consumer_url = self.SHIB_CONSUMER_URL
        self.saml2plugin.saml2_authn_request = etree.XML(
            saml2_fixtures.SP_SOAP_RESPONSE)
        self.saml2plugin._send_idp_saml2_authn_request(self.session)

        idp_response = etree.tostring(
            self.saml2plugin.saml2_idp_authn_response)

        self.assertThat(idp_response,
                        matchers.XMLEquals(saml2_fixtures.SAML2_ASSERTION))

    def test_fail_basicauth_idp_authentication(self):
        self.requests_mock.post(self.IDENTITY_PROVIDER_URL,
                                status_code=401)

        self.saml2plugin.sp_response_consumer_url = self.SHIB_CONSUMER_URL
        self.saml2plugin.saml2_authn_request = etree.XML(
            saml2_fixtures.SP_SOAP_RESPONSE)
        self.assertRaises(
            exceptions.Unauthorized,
            self.saml2plugin._send_idp_saml2_authn_request,
            self.session)

    def test_mising_username_password_in_plugin(self):
        self.assertRaises(TypeError,
                          saml2.V3Saml2Password,
                          self.TEST_URL, self.IDENTITY_PROVIDER,
                          self.IDENTITY_PROVIDER_URL)

    def test_send_authn_response_to_sp(self):
        self.requests_mock.post(
            self.SHIB_CONSUMER_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        self.saml2plugin.relay_state = etree.XML(
            saml2_fixtures.SP_SOAP_RESPONSE).xpath(
            self.ECP_RELAY_STATE, namespaces=self.ECP_SAML2_NAMESPACES)[0]

        self.saml2plugin.saml2_idp_authn_response = etree.XML(
            saml2_fixtures.SAML2_ASSERTION)

        self.saml2plugin.idp_response_consumer_url = self.SHIB_CONSUMER_URL
        self.saml2plugin._send_service_provider_saml2_authn_response(
            self.session)
        token_json = self.saml2plugin.authenticated_response.json()['token']
        token = self.saml2plugin.authenticated_response.headers[
            'X-Subject-Token']
        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN['token'],
                         token_json)

        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                         token)

    def test_consumer_url_mismatch_success(self):
        self.saml2plugin._check_consumer_urls(
            self.session, self.SHIB_CONSUMER_URL,
            self.SHIB_CONSUMER_URL)

    def test_consumer_url_mismatch(self):
        self.requests_mock.post(self.SHIB_CONSUMER_URL)
        invalid_consumer_url = uuid.uuid4().hex
        self.assertRaises(
            exceptions.AuthorizationFailure,
            self.saml2plugin._check_consumer_urls,
            self.session, self.SHIB_CONSUMER_URL,
            invalid_consumer_url)

    def test_custom_302_redirection(self):
        self.requests_mock.post(
            self.SHIB_CONSUMER_URL,
            text='BODY',
            headers={'location': self.FEDERATION_AUTH_URL},
            status_code=302)

        self.requests_mock.get(
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        self.session.redirect = False
        response = self.session.post(
            self.SHIB_CONSUMER_URL, data='CLIENT BODY')
        self.assertEqual(302, response.status_code)
        self.assertEqual(self.FEDERATION_AUTH_URL,
                         response.headers['location'])

        response = self.saml2plugin._handle_http_ecp_redirect(
            self.session, response, 'GET')

        self.assertEqual(self.FEDERATION_AUTH_URL, response.request.url)
        self.assertEqual('GET', response.request.method)

    def test_custom_303_redirection(self):
        self.requests_mock.post(
            self.SHIB_CONSUMER_URL,
            text='BODY',
            headers={'location': self.FEDERATION_AUTH_URL},
            status_code=303)

        self.requests_mock.get(
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        self.session.redirect = False
        response = self.session.post(
            self.SHIB_CONSUMER_URL, data='CLIENT BODY')
        self.assertEqual(303, response.status_code)
        self.assertEqual(self.FEDERATION_AUTH_URL,
                         response.headers['location'])

        response = self.saml2plugin._handle_http_ecp_redirect(
            self.session, response, 'GET')

        self.assertEqual(self.FEDERATION_AUTH_URL, response.request.url)
        self.assertEqual('GET', response.request.method)

    def test_end_to_end_workflow(self):
        self.requests_mock.get(
            self.FEDERATION_AUTH_URL,
            content=utils.make_oneline(saml2_fixtures.SP_SOAP_RESPONSE))

        self.requests_mock.post(self.IDENTITY_PROVIDER_URL,
                                content=saml2_fixtures.SAML2_ASSERTION)

        self.requests_mock.post(
            self.SHIB_CONSUMER_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                     'Content-Type': 'application/json'})

        self.session.redirect = False
        response = self.saml2plugin.get_auth_ref(self.session)
        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                         response.auth_token)
