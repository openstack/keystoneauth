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

from keystoneauth1.loading._plugins.identity import generic
from keystoneauth1.tests.unit.loading import utils


class PasswordTests(utils.TestCase):

    def test_options(self):
        opts = [o.name for o in generic.Password().get_options()]

        allowed_opts = ['user-name',
                        'user-domain-id',
                        'user-domain-name',
                        'user-id',
                        'password',

                        'domain-id',
                        'domain-name',
                        'project-id',
                        'project-name',
                        'project-domain-id',
                        'project-domain-name',
                        'trust-id',
                        'auth-url']

        self.assertEqual(set(allowed_opts), set(opts))
        self.assertEqual(len(allowed_opts), len(opts))


class TokenTests(utils.TestCase):

    def test_options(self):
        opts = [o.name for o in generic.Token().get_options()]

        allowed_opts = ['token',
                        'domain-id',
                        'domain-name',
                        'project-id',
                        'project-name',
                        'project-domain-id',
                        'project-domain-name',
                        'trust-id',
                        'auth-url']

        self.assertEqual(set(allowed_opts), set(opts))
        self.assertEqual(len(allowed_opts), len(opts))
