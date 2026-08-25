# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy
import datetime
import json
import uuid

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1 import fixture
from keystoneauth1 import identity
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneauth1.tests.unit import k2k_fixtures
from keystoneauth1.tests.unit import utils


class TesterFederationPlugin(v3.FederationBaseAuth):
    def get_unscoped_auth_ref(self, sess):
        # This would go and talk to an idp or something
        resp = sess.post(self.federated_token_url, authenticated=False)
        return access.create(resp=resp)


class V3FederatedPluginBase(utils.TestCase):
    """Fixtures for a federated plugin, without any tests of its own.

    Separate from the tests so that another test class can reuse the setup
    without also inheriting and rerunning them.
    """

    AUTH_URL = 'http://keystone/v3'

    def setUp(self):
        super().setUp()

        self.unscoped_token = fixture.V3Token()
        self.unscoped_token_id = uuid.uuid4().hex
        self.scoped_token = copy.deepcopy(self.unscoped_token)
        self.scoped_token.set_project_scope()
        self.scoped_token.methods.append('token')
        self.scoped_token_id = uuid.uuid4().hex

        s = self.scoped_token.add_service('compute', name='nova')
        s.add_standard_endpoints(
            public='http://nova/public',
            admin='http://nova/admin',
            internal='http://nova/internal',
        )

        self.idp = uuid.uuid4().hex
        self.protocol = uuid.uuid4().hex

        self.token_url = (
            f'{self.AUTH_URL}/OS-FEDERATION/identity_providers/{self.idp}/protocols/{self.protocol}'
            '/auth'
        )

        headers = {'X-Subject-Token': self.unscoped_token_id}
        self.unscoped_mock = self.requests_mock.post(
            self.token_url, json=self.unscoped_token, headers=headers
        )

        headers = {'X-Subject-Token': self.scoped_token_id}
        auth_url = self.AUTH_URL + '/auth/tokens'
        self.scoped_mock = self.requests_mock.post(
            auth_url, json=self.scoped_token, headers=headers
        )

    def get_plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.AUTH_URL)
        kwargs.setdefault('protocol', self.protocol)
        kwargs.setdefault('identity_provider', self.idp)
        return TesterFederationPlugin(**kwargs)


class V3FederatedPlugin(V3FederatedPluginBase):
    def test_federated_url(self):
        plugin = self.get_plugin()
        self.assertEqual(self.token_url, plugin.federated_token_url)

    def test_federated_url_unversioned(self):
        plugin = self.get_plugin(auth_url="http://keystone/")
        self.assertEqual(self.token_url, plugin.federated_token_url)

    def test_unscoped_behaviour(self):
        sess = session.Session(auth=self.get_plugin())
        self.assertEqual(self.unscoped_token_id, sess.get_token())

        self.assertTrue(self.unscoped_mock.called)
        self.assertFalse(self.scoped_mock.called)

    def test_scoped_behaviour(self):
        auth = self.get_plugin(project_id=self.scoped_token.project_id)
        sess = session.Session(auth=auth)
        self.assertEqual(self.scoped_token_id, sess.get_token())

        self.assertTrue(self.unscoped_mock.called)
        self.assertTrue(self.scoped_mock.called)

    def test_scoped_behaviour_for_each_scope(self):
        # Every scope the plugin accepts has to reach the rescoping request.
        # Silently returning the unscoped token instead leaves the caller
        # authenticated as nobody in particular, which only shows up later as
        # an unexplained 403 or 404 from whatever they were trying to reach.
        scopes = [
            (
                'project',
                {
                    'project_id': uuid.uuid4().hex,
                    'project_domain_id': uuid.uuid4().hex,
                },
            ),
            ('domain', {'domain_id': uuid.uuid4().hex}),
            ('system', {'system_scope': 'all'}),
            ('trust', {'trust_id': uuid.uuid4().hex}),
        ]

        for description, kwargs in scopes:
            with self.subTest(description):
                sess = session.Session(auth=self.get_plugin(**kwargs))

                self.assertEqual(self.scoped_token_id, sess.get_token())

                scope = self.scoped_mock.last_request.json()['auth']['scope']
                self.assertIsNotNone(scope)


class K2KAuthPluginTest(utils.TestCase):
    TEST_ROOT_URL = 'http://127.0.0.1:5000/'
    TEST_URL = '{}{}'.format(TEST_ROOT_URL, 'v3')
    TEST_PASS = 'password'

    REQUEST_ECP_URL = TEST_URL + '/auth/OS-FEDERATION/saml2/ecp'

    SP_ROOT_URL = 'https://sp1.com/v3'
    SP_ID = 'sp1'
    SP_URL = 'https://sp1.com/Shibboleth.sso/SAML2/ECP'
    SP_AUTH_URL = (
        SP_ROOT_URL + '/OS-FEDERATION/identity_providers'
        '/testidp/protocols/saml2/auth'
    )

    SERVICE_PROVIDER_DICT = {
        'id': SP_ID,
        'auth_url': SP_AUTH_URL,
        'sp_url': SP_URL,
    }

    def setUp(self):
        super().setUp()
        self.token_v3 = fixture.V3Token()
        self.token_v3.add_service_provider(
            self.SP_ID, self.SP_AUTH_URL, self.SP_URL
        )
        self.session = session.Session()

        self.k2kplugin = self.get_plugin()

    def _get_base_plugin(self):
        self.stub_url(
            'POST',
            ['auth', 'tokens'],
            headers={'X-Subject-Token': uuid.uuid4().hex},
            json=self.token_v3,
        )
        return v3.Password(
            self.TEST_URL, username=self.TEST_USER, password=self.TEST_PASS
        )

    def _mock_k2k_flow_urls(self, redirect_code=302):
        # List versions available for auth
        self.requests_mock.get(
            self.TEST_URL,
            json={'version': fixture.V3Discovery(self.TEST_URL)},
            headers={'Content-Type': 'application/json'},
        )

        # The IdP should return a ECP wrapped assertion when requested
        self.requests_mock.register_uri(
            'POST',
            self.REQUEST_ECP_URL,
            content=bytes(k2k_fixtures.ECP_ENVELOPE, 'latin-1'),
            headers={'Content-Type': 'application/vnd.paos+xml'},
            status_code=200,
        )

        # The SP should respond with a redirect (302 or 303)
        self.requests_mock.register_uri(
            'POST',
            self.SP_URL,
            content=bytes(k2k_fixtures.TOKEN_BASED_ECP, 'latin-1'),
            headers={'Content-Type': 'application/vnd.paos+xml'},
            status_code=redirect_code,
        )

        # Should not follow the redirect URL, but use the auth_url attribute
        self.requests_mock.register_uri(
            'GET',
            self.SP_AUTH_URL,
            json=k2k_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': k2k_fixtures.UNSCOPED_TOKEN_HEADER},
        )

    def get_plugin(self, **kwargs):
        kwargs.setdefault('base_plugin', self._get_base_plugin())
        kwargs.setdefault('service_provider', self.SP_ID)
        return v3.Keystone2Keystone(**kwargs)

    def test_remote_url(self):
        remote_auth_url = self.k2kplugin._remote_auth_url(self.SP_AUTH_URL)
        self.assertEqual(self.SP_ROOT_URL, remote_auth_url)

    def test_fail_getting_ecp_assertion(self):
        self.requests_mock.get(
            self.TEST_URL,
            json={'version': fixture.V3Discovery(self.TEST_URL)},
            headers={'Content-Type': 'application/json'},
        )

        self.requests_mock.register_uri(
            'POST', self.REQUEST_ECP_URL, status_code=401
        )

        self.assertRaises(
            exceptions.AuthorizationFailure,
            self.k2kplugin._get_ecp_assertion,
            self.session,
        )

    def test_get_ecp_assertion_empty_response(self):
        self.requests_mock.get(
            self.TEST_URL,
            json={'version': fixture.V3Discovery(self.TEST_URL)},
            headers={'Content-Type': 'application/json'},
        )

        self.requests_mock.register_uri(
            'POST',
            self.REQUEST_ECP_URL,
            headers={'Content-Type': 'application/vnd.paos+xml'},
            content=b'',
            status_code=200,
        )

        self.assertRaises(
            exceptions.InvalidResponse,
            self.k2kplugin._get_ecp_assertion,
            self.session,
        )

    def test_get_ecp_assertion_wrong_headers(self):
        self.requests_mock.get(
            self.TEST_URL,
            json={'version': fixture.V3Discovery(self.TEST_URL)},
            headers={'Content-Type': 'application/json'},
        )

        self.requests_mock.register_uri(
            'POST',
            self.REQUEST_ECP_URL,
            headers={'Content-Type': uuid.uuid4().hex},
            content=b'',
            status_code=200,
        )

        self.assertRaises(
            exceptions.InvalidResponse,
            self.k2kplugin._get_ecp_assertion,
            self.session,
        )

    def test_send_ecp_authn_response(self):
        self._mock_k2k_flow_urls()
        # Perform the request
        response = self.k2kplugin._send_service_provider_ecp_authn_response(
            self.session, self.SP_URL, self.SP_AUTH_URL
        )

        # Check the response
        self.assertEqual(
            k2k_fixtures.UNSCOPED_TOKEN_HEADER,
            response.headers['X-Subject-Token'],
        )

    def test_send_ecp_authn_response_303_redirect(self):
        self._mock_k2k_flow_urls(redirect_code=303)
        # Perform the request
        response = self.k2kplugin._send_service_provider_ecp_authn_response(
            self.session, self.SP_URL, self.SP_AUTH_URL
        )

        # Check the response
        self.assertEqual(
            k2k_fixtures.UNSCOPED_TOKEN_HEADER,
            response.headers['X-Subject-Token'],
        )

    def test_end_to_end_workflow(self):
        self._mock_k2k_flow_urls()
        auth_ref = self.k2kplugin.get_auth_ref(self.session)
        self.assertEqual(
            k2k_fixtures.UNSCOPED_TOKEN_HEADER, auth_ref.auth_token
        )

    def test_end_to_end_workflow_303_redirect(self):
        self._mock_k2k_flow_urls(redirect_code=303)
        auth_ref = self.k2kplugin.get_auth_ref(self.session)
        self.assertEqual(
            k2k_fixtures.UNSCOPED_TOKEN_HEADER, auth_ref.auth_token
        )

    def test_end_to_end_with_generic_password(self):
        # List versions available for auth
        self.requests_mock.get(
            self.TEST_ROOT_URL,
            json=fixture.DiscoveryList(self.TEST_ROOT_URL),
            headers={'Content-Type': 'application/json'},
        )

        # The IdP should return a ECP wrapped assertion when requested
        self.requests_mock.register_uri(
            'POST',
            self.REQUEST_ECP_URL,
            content=bytes(k2k_fixtures.ECP_ENVELOPE, 'latin-1'),
            headers={'Content-Type': 'application/vnd.paos+xml'},
            status_code=200,
        )

        # The SP should respond with a redirect (302 or 303)
        self.requests_mock.register_uri(
            'POST',
            self.SP_URL,
            content=bytes(k2k_fixtures.TOKEN_BASED_ECP, 'latin-1'),
            headers={'Content-Type': 'application/vnd.paos+xml'},
            status_code=302,
        )

        # Should not follow the redirect URL, but use the auth_url attribute
        self.requests_mock.register_uri(
            'GET',
            self.SP_AUTH_URL,
            json=k2k_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': k2k_fixtures.UNSCOPED_TOKEN_HEADER},
        )

        self.stub_url(
            'POST',
            ['auth', 'tokens'],
            headers={'X-Subject-Token': uuid.uuid4().hex},
            json=self.token_v3,
        )

        plugin = identity.Password(
            self.TEST_ROOT_URL,
            username=self.TEST_USER,
            password=self.TEST_PASS,
            user_domain_id='default',
        )

        k2kplugin = self.get_plugin(base_plugin=plugin)
        self.assertEqual(
            k2k_fixtures.UNSCOPED_TOKEN_HEADER,
            k2kplugin.get_token(self.session),
        )


class V3FederatedUnscopedState(V3FederatedPluginBase):
    """The API a caller uses to hold on to the unscoped token itself."""

    def test_state_is_empty_before_authenticating(self):
        self.assertIsNone(self.get_plugin().get_unscoped_auth_state())

    def test_one_unscoped_token_serves_every_scope(self):
        origin = self.get_plugin()
        session.Session(auth=origin).get_token()
        state = origin.get_unscoped_auth_state()

        self.assertIsNotNone(state)
        self.assertEqual(1, self.unscoped_mock.call_count)

        scopes = [
            {'project_id': self.scoped_token.project_id},
            {'domain_id': uuid.uuid4().hex},
            {'system_scope': 'all'},
            {'trust_id': uuid.uuid4().hex},
        ]

        for kwargs in scopes:
            with self.subTest(next(iter(kwargs))):
                plugin = self.get_plugin(**kwargs)
                plugin.set_unscoped_auth_state(state)

                self.assertEqual(
                    self.scoped_token_id,
                    session.Session(auth=plugin).get_token(),
                )

        # One authentication, and a rescope for each of the scopes.
        self.assertEqual(1, self.unscoped_mock.call_count)
        self.assertEqual(len(scopes), self.scoped_mock.call_count)

    def test_cache_id_ignores_the_scope_but_not_the_identity(self):
        base_id = self.get_plugin().get_unscoped_cache_id()
        self.assertIsNotNone(base_id)

        for kwargs in (
            {'project_id': uuid.uuid4().hex},
            {'domain_id': uuid.uuid4().hex},
            {'system_scope': 'all'},
            {'trust_id': uuid.uuid4().hex},
        ):
            with self.subTest(f'unchanged by {next(iter(kwargs))}'):
                self.assertEqual(
                    base_id, self.get_plugin(**kwargs).get_unscoped_cache_id()
                )

        for description, kwargs in (
            ('identity provider', {'identity_provider': uuid.uuid4().hex}),
            ('protocol', {'protocol': uuid.uuid4().hex}),
            ('auth url', {'auth_url': 'http://elsewhere/v3'}),
            # 'foo'/'bar' against 'foob'/'ar' needs the elements terminated
            # rather than simply concatenated.
            (
                'element boundaries',
                {'identity_provider': 'foo', 'protocol': 'bar'},
            ),
        ):
            with self.subTest(f'changed by {description}'):
                self.assertNotEqual(
                    base_id, self.get_plugin(**kwargs).get_unscoped_cache_id()
                )

    def test_expired_state_is_replaced(self):
        expired = fixture.V3Token()
        expired.expires = datetime.datetime.now(
            datetime.UTC
        ) - datetime.timedelta(hours=1)
        plugin = self.get_plugin(project_id=self.scoped_token.project_id)
        plugin.set_unscoped_auth_state(
            json.dumps({'auth_token': uuid.uuid4().hex, 'body': expired})
        )

        session.Session(auth=plugin).get_token()

        self.assertEqual(1, self.unscoped_mock.call_count)

    def test_a_refused_unscoped_token_is_replaced(self):
        # A revoked token is not expired, so nothing about it says it will be
        # refused until the rescope is. The rescope carries the token in its
        # body rather than a header, so the session cannot retry it either.
        plugin = self.get_plugin(project_id=self.scoped_token.project_id)
        plugin.set_unscoped_auth_state(
            json.dumps({'auth_token': 'revoked', 'body': fixture.V3Token()})
        )

        def rescope(request, context):
            token = request.json()['auth']['identity']['token']['id']
            if token == 'revoked':
                context.status_code = 401
                return {'error': {'message': 'revoked'}}
            context.status_code = 201
            context.headers['X-Subject-Token'] = self.scoped_token_id
            return self.scoped_token

        self.scoped_mock = self.requests_mock.post(
            self.AUTH_URL + '/auth/tokens', json=rescope
        )

        self.assertEqual(
            self.scoped_token_id, session.Session(auth=plugin).get_token()
        )
        self.assertEqual(1, self.unscoped_mock.call_count)

    def test_a_refused_fresh_unscoped_token_is_not_retried(self):
        # Authenticating again would only produce the same refusal, so the
        # error belongs to the caller rather than another round trip.
        self.requests_mock.post(
            self.AUTH_URL + '/auth/tokens',
            status_code=401,
            json={'error': {'message': 'nope'}},
        )
        plugin = self.get_plugin(project_id=self.scoped_token.project_id)

        self.assertRaises(
            exceptions.Unauthorized, session.Session(auth=plugin).get_token
        )
        self.assertEqual(1, self.unscoped_mock.call_count)

    def test_invalidate_discards_the_unscoped_token(self):
        plugin = self.get_plugin(project_id=self.scoped_token.project_id)
        session.Session(auth=plugin).get_token()
        self.assertIsNotNone(plugin.get_unscoped_auth_state())

        self.assertTrue(plugin.invalidate())

        # Otherwise the retry after an unauthorized response would rescope
        # from a token the identity service has already refused.
        self.assertIsNone(plugin.get_unscoped_auth_state())

    def test_state_that_did_not_come_from_here_is_refused(self):
        plugin = self.get_plugin()

        for data in (
            '{}',
            '{"auth_token": "x"}',
            '{"body": {"access": {}}}',
            # Valid JSON, but not the object shape this API produces. These
            # come back from persistent storage, where stale or malformed
            # data is possible, so they must be a ValueError rather than the
            # TypeError the key lookup would otherwise raise.
            '[]',
            'null',
            '"x"',
        ):
            with self.subTest(data):
                self.assertRaises(
                    ValueError, plugin.set_unscoped_auth_state, data
                )

    def test_empty_state_clears(self):
        plugin = self.get_plugin(project_id=self.scoped_token.project_id)
        session.Session(auth=plugin).get_token()

        plugin.set_unscoped_auth_state(None)

        self.assertIsNone(plugin.get_unscoped_auth_state())

    def test_interactive_flows_are_marked(self):
        for plugin_class, interactive in (
            (identity.V3OidcAuthorizationCode, True),
            (identity.V3OidcDeviceAuthorization, True),
            (identity.V3OidcPassword, False),
            (identity.V3OidcClientCredentials, False),
        ):
            with self.subTest(plugin_class.__name__):
                self.assertEqual(
                    interactive, plugin_class.interactive_unscoped_auth
                )
