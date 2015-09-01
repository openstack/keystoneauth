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

from keystoneauth1 import exceptions
from keystoneauth1 import loading
from keystoneauth1.tests.unit.loading import utils


class V3PasswordTests(utils.TestCase):

    def setUp(self):
        super(V3PasswordTests, self).setUp()

        self.auth_url = uuid.uuid4().hex

    def create(self, **kwargs):
        kwargs.setdefault('auth_url', self.auth_url)
        loader = loading.get_plugin_loader('v3password')
        return loader.load_from_options(**kwargs)

    def test_basic(self):
        username = uuid.uuid4().hex
        user_domain_id = uuid.uuid4().hex
        password = uuid.uuid4().hex
        project_name = uuid.uuid4().hex
        project_domain_id = uuid.uuid4().hex

        p = self.create(username=username,
                        user_domain_id=user_domain_id,
                        project_name=project_name,
                        project_domain_id=project_domain_id,
                        password=password)

        pw_method = p.auth_methods[0]

        self.assertEqual(username, pw_method.username)
        self.assertEqual(user_domain_id, pw_method.user_domain_id)
        self.assertEqual(password, pw_method.password)

        self.assertEqual(project_name, p.project_name)
        self.assertEqual(project_domain_id, p.project_domain_id)

    def test_without_user_domain(self):
        self.assertRaises(exceptions.OptionError,
                          self.create,
                          username=uuid.uuid4().hex,
                          password=uuid.uuid4().hex)

    def test_without_project_domain(self):
        self.assertRaises(exceptions.OptionError,
                          self.create,
                          username=uuid.uuid4().hex,
                          password=uuid.uuid4().hex,
                          user_domain_id=uuid.uuid4().hex,
                          project_name=uuid.uuid4().hex)
