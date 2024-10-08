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

import uuid

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1 import fixture
from keystoneauth1 import session
from keystoneauth1.tests.unit import utils


class GenericPluginTestCase(utils.TestCase):
    TEST_URL = 'http://keystone.host:5000/'

    # OVERRIDE THESE IN SUB CLASSES
    PLUGIN_CLASS = None
    V2_PLUGIN_CLASS = None
    V3_PLUGIN_CLASS = None

    def setUp(self):
        super().setUp()

        self.token_v2 = fixture.V2Token()
        self.token_v3 = fixture.V3Token()
        self.token_v3_id = uuid.uuid4().hex
        self.session = session.Session()

        self.stub_url('POST', ['v2.0', 'tokens'], json=self.token_v2)
        self.stub_url(
            'POST',
            ['v3', 'auth', 'tokens'],
            headers={'X-Subject-Token': self.token_v3_id},
            json=self.token_v3,
        )

    def new_plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.TEST_URL)
        return self.PLUGIN_CLASS(**kwargs)

    def stub_discovery(self, base_url=None, **kwargs):
        kwargs.setdefault('href', self.TEST_URL)
        disc = fixture.DiscoveryList(**kwargs)
        self.stub_url('GET', json=disc, base_url=base_url, status_code=300)
        return disc

    def assertCreateV3(self, **kwargs):
        auth = self.new_plugin(**kwargs)
        auth_ref = auth.get_auth_ref(self.session)
        self.assertIsInstance(auth_ref, access.AccessInfoV3)
        self.assertEqual(
            self.TEST_URL + 'v3/auth/tokens',
            self.requests_mock.last_request.url,
        )
        self.assertIsInstance(auth._plugin, self.V3_PLUGIN_CLASS)
        return auth

    def assertCreateV2(self, **kwargs):
        auth = self.new_plugin(**kwargs)
        auth_ref = auth.get_auth_ref(self.session)
        self.assertIsInstance(auth_ref, access.AccessInfoV2)
        self.assertEqual(
            self.TEST_URL + 'v2.0/tokens', self.requests_mock.last_request.url
        )
        self.assertIsInstance(auth._plugin, self.V2_PLUGIN_CLASS)
        return auth

    def assertDiscoveryFailure(self, **kwargs):
        plugin = self.new_plugin(**kwargs)
        self.assertRaises(
            exceptions.DiscoveryFailure, plugin.get_auth_ref, self.session
        )

    def test_create_v3_if_domain_params(self):
        self.stub_discovery()

        self.assertCreateV3(domain_id=uuid.uuid4().hex)
        self.assertCreateV3(domain_name=uuid.uuid4().hex)
        self.assertCreateV3(
            project_name=uuid.uuid4().hex, project_domain_name=uuid.uuid4().hex
        )
        self.assertCreateV3(
            project_name=uuid.uuid4().hex, project_domain_id=uuid.uuid4().hex
        )

    def test_create_v2_if_no_domain_params(self):
        self.stub_discovery()
        self.assertCreateV2()
        self.assertCreateV2(project_id=uuid.uuid4().hex)
        self.assertCreateV2(project_name=uuid.uuid4().hex)
        self.assertCreateV2(tenant_id=uuid.uuid4().hex)
        self.assertCreateV2(tenant_name=uuid.uuid4().hex)

    def test_create_plugin_no_reauthenticate(self):
        self.stub_discovery()
        self.assertCreateV2(reauthenticate=False)
        self.assertCreateV3(domain_id=uuid.uuid4().hex, reauthenticate=False)

    def test_v3_params_v2_url(self):
        self.stub_discovery(v3=False)
        self.assertDiscoveryFailure(domain_name=uuid.uuid4().hex)

    def test_v2_params_v3_url(self):
        self.stub_discovery(v2=False)
        self.assertCreateV3()

    def test_no_urls(self):
        self.stub_discovery(v2=False, v3=False)
        self.assertDiscoveryFailure()

    def test_path_based_url_v2(self):
        self.stub_url('GET', ['v2.0'], status_code=403)
        self.assertCreateV2(auth_url=self.TEST_URL + 'v2.0')

    def test_path_based_url_v3(self):
        self.stub_url('GET', ['v3'], status_code=403)
        self.assertCreateV3(auth_url=self.TEST_URL + 'v3')

    def test_disc_error_for_failure(self):
        self.stub_url('GET', [], status_code=403)
        self.assertDiscoveryFailure()
        self.assertIn(self.TEST_URL, self.logger.output)

    def test_v3_plugin_from_failure(self):
        url = self.TEST_URL + 'v3'
        self.stub_url('GET', [], base_url=url, status_code=403)
        self.assertCreateV3(auth_url=url)

    def test_unknown_discovery_version(self):
        # make a v4 entry that's mostly the same as a v3
        self.stub_discovery(v2=False, v3_id='v4.0')
        self.assertDiscoveryFailure()

    def test_default_domain_id_with_v3(self, **kwargs):
        self.stub_discovery()
        project_name = uuid.uuid4().hex
        default_domain_id = kwargs.setdefault(
            'default_domain_id', uuid.uuid4().hex
        )

        p = self.assertCreateV3(project_name=project_name, **kwargs)

        self.assertEqual(default_domain_id, p._plugin.project_domain_id)
        self.assertEqual(project_name, p._plugin.project_name)

        return p

    def test_default_domain_id_no_v3(self):
        self.stub_discovery(v3=False)
        project_name = uuid.uuid4().hex
        default_domain_id = uuid.uuid4().hex

        p = self.assertCreateV2(
            project_name=project_name, default_domain_id=default_domain_id
        )

        self.assertEqual(project_name, p._plugin.tenant_name)

    def test_default_domain_name_with_v3(self, **kwargs):
        self.stub_discovery()
        project_name = uuid.uuid4().hex
        default_domain_name = kwargs.setdefault(
            'default_domain_name', uuid.uuid4().hex
        )

        p = self.assertCreateV3(project_name=project_name, **kwargs)

        self.assertEqual(default_domain_name, p._plugin.project_domain_name)
        self.assertEqual(project_name, p._plugin.project_name)

        return p

    def test_default_domain_name_no_v3(self):
        self.stub_discovery(v3=False)
        project_name = uuid.uuid4().hex
        default_domain_name = uuid.uuid4().hex

        p = self.assertCreateV2(
            project_name=project_name, default_domain_name=default_domain_name
        )

        self.assertEqual(project_name, p._plugin.tenant_name)
