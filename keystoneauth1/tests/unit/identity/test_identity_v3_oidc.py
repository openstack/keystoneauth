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

from six.moves import urllib

from keystoneauth1.identity.v3 import oidc
from keystoneauth1 import session
from keystoneauth1.tests.unit import oidc_fixtures
from keystoneauth1.tests.unit import utils


KEYSTONE_TOKEN_VALUE = uuid.uuid4().hex


class AuthenticateOIDCTests(utils.TestCase):

    def setUp(self):
        super(AuthenticateOIDCTests, self).setUp()
        self.session = session.Session()

        self.AUTH_URL = 'http://keystone:5000/v3'
        self.IDENTITY_PROVIDER = 'bluepages'
        self.PROTOCOL = 'oidc'
        self.USER_NAME = 'oidc_user@example.com'
        self.PASSWORD = uuid.uuid4().hex
        self.CLIENT_ID = uuid.uuid4().hex
        self.CLIENT_SECRET = uuid.uuid4().hex
        self.ACCESS_TOKEN_ENDPOINT = 'https://localhost:8020/oidc/token'
        self.FEDERATION_AUTH_URL = '%s/%s' % (
            self.AUTH_URL,
            'OS-FEDERATION/identity_providers/bluepages/protocols/oidc/auth')
        self.REDIRECT_URL = 'urn:ietf:wg:oauth:2.0:oob'
        self.CODE = '4/M9TNz2G9WVwYxSjx0w9AgA1bOmryJltQvOhQMq0czJs.cnLNVAfqwG'

        self.oidc_password = oidc.OidcPassword(
            self.AUTH_URL,
            self.IDENTITY_PROVIDER,
            self.PROTOCOL,
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET,
            access_token_endpoint=self.ACCESS_TOKEN_ENDPOINT,
            username=self.USER_NAME,
            password=self.PASSWORD)

        self.oidc_grant = oidc.OidcAuthorizationCode(
            self.AUTH_URL,
            self.IDENTITY_PROVIDER,
            self.PROTOCOL,
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET,
            access_token_endpoint=self.ACCESS_TOKEN_ENDPOINT,
            redirect_uri=self.REDIRECT_URL,
            code=self.CODE)


class OIDCPasswordTests(AuthenticateOIDCTests):

    def test_initial_call_to_get_access_token(self):
        """Test initial call, expect JSON access token."""

        # Mock the output that creates the access token
        self.requests_mock.post(
            self.ACCESS_TOKEN_ENDPOINT,
            json=oidc_fixtures.ACCESS_TOKEN_VIA_PASSWORD_RESP)

        # Prep all the values and send the request
        grant_type = 'password'
        scope = 'profile email'
        client_auth = (self.CLIENT_ID, self.CLIENT_SECRET)
        payload = {'grant_type': grant_type, 'username': self.USER_NAME,
                   'password': self.PASSWORD, 'scope': scope}
        res = self.oidc_password._get_access_token(self.session,
                                                   client_auth,
                                                   payload,
                                                   self.ACCESS_TOKEN_ENDPOINT)

        # Verify the request matches the expected structure
        self.assertEqual(self.ACCESS_TOKEN_ENDPOINT, res.request.url)
        self.assertEqual('POST', res.request.method)
        encoded_payload = urllib.parse.urlencode(payload)
        self.assertEqual(encoded_payload, res.request.body)

    def test_second_call_to_protected_url(self):
        """Test subsequent call, expect Keystone token."""

        # Mock the output that creates the keystone token
        self.requests_mock.post(
            self.FEDERATION_AUTH_URL,
            json=oidc_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': KEYSTONE_TOKEN_VALUE})

        # Prep all the values and send the request
        access_token = uuid.uuid4().hex
        headers = {'Authorization': 'Bearer ' + access_token}
        res = self.oidc_password._get_keystone_token(self.session,
                                                     headers,
                                                     self.FEDERATION_AUTH_URL)

        # Verify the request matches the expected structure
        self.assertEqual(self.FEDERATION_AUTH_URL, res.request.url)
        self.assertEqual('POST', res.request.method)
        self.assertEqual(headers['Authorization'],
                         res.request.headers['Authorization'])

    def test_end_to_end_workflow(self):
        """Test full OpenID Connect workflow."""

        # Mock the output that creates the access token
        self.requests_mock.post(
            self.ACCESS_TOKEN_ENDPOINT,
            json=oidc_fixtures.ACCESS_TOKEN_VIA_PASSWORD_RESP)

        # Mock the output that creates the keystone token
        self.requests_mock.post(
            self.FEDERATION_AUTH_URL,
            json=oidc_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': KEYSTONE_TOKEN_VALUE})

        response = self.oidc_password.get_unscoped_auth_ref(self.session)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, response.auth_token)


class OIDCAuthorizationGrantTests(AuthenticateOIDCTests):

    def test_initial_call_to_get_access_token(self):
        """Test initial call, expect JSON access token."""

        # Mock the output that creates the access token
        self.requests_mock.post(
            self.ACCESS_TOKEN_ENDPOINT,
            json=oidc_fixtures.ACCESS_TOKEN_VIA_AUTH_GRANT_RESP)

        # Prep all the values and send the request
        grant_type = 'authorization_code'
        client_auth = (self.CLIENT_ID, self.CLIENT_SECRET)
        payload = {'grant_type': grant_type,
                   'redirect_uri': self.REDIRECT_URL,
                   'code': self.CODE}
        res = self.oidc_grant._get_access_token(self.session,
                                                client_auth,
                                                payload,
                                                self.ACCESS_TOKEN_ENDPOINT)

        # Verify the request matches the expected structure
        self.assertEqual(self.ACCESS_TOKEN_ENDPOINT, res.request.url)
        self.assertEqual('POST', res.request.method)
        encoded_payload = urllib.parse.urlencode(payload)
        self.assertEqual(encoded_payload, res.request.body)
