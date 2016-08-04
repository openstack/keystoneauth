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

import testtools

from betamax import exceptions

from keystoneauth1.fixture import keystoneauth_betamax
from keystoneauth1.fixture import v2 as v2Fixtures
from keystoneauth1.identity import v2
from keystoneauth1 import session


class TestBetamaxFixture(testtools.TestCase):

    TEST_USERNAME = 'test_user_name'
    TEST_PASSWORD = 'test_password'
    TEST_TENANT_NAME = 'test_tenant_name'
    TEST_AUTH_URL = 'http://keystoneauth.betamax_test/v2.0/'

    V2_TOKEN = v2Fixtures.Token(tenant_name=TEST_TENANT_NAME,
                                user_name=TEST_USERNAME)

    def setUp(self):
        super(TestBetamaxFixture, self).setUp()
        self.ksa_betamax_fixture = self.useFixture(
            keystoneauth_betamax.BetamaxFixture(
                cassette_name='ksa_betamax_test_cassette',
                cassette_library_dir='keystoneauth1/tests/unit/data/',
                record=False))

    def _replay_cassette(self):
        plugin = v2.Password(
            auth_url=self.TEST_AUTH_URL,
            password=self.TEST_PASSWORD,
            username=self.TEST_USERNAME,
            tenant_name=self.TEST_TENANT_NAME)
        s = session.Session()
        s.get_token(auth=plugin)

    def test_keystoneauth_betamax_fixture(self):
        self._replay_cassette()

    def test_replay_of_bad_url_fails(self):
        plugin = v2.Password(
            auth_url='http://invalid-auth-url/v2.0/',
            password=self.TEST_PASSWORD,
            username=self.TEST_USERNAME,
            tenant_name=self.TEST_TENANT_NAME)
        s = session.Session()
        self.assertRaises(exceptions.BetamaxError, s.get_token, auth=plugin)
