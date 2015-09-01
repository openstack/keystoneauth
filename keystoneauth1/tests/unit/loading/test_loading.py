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


class LoadingTests(utils.TestCase):

    def test_required_values(self):
        opts = [loading.Opt('a', required=False),
                loading.Opt('b', required=True)]

        Plugin, Loader = utils.create_plugin(opts=opts)

        l = Loader()
        v = uuid.uuid4().hex

        p1 = l.load_from_options(b=v)
        self.assertEqual(v, p1['b'])

        e = self.assertRaises(exceptions.MissingRequiredOptions,
                              l.load_from_options,
                              a=v)

        self.assertEqual(1, len(e.options))

        for o in e.options:
            self.assertIsInstance(o, loading.Opt)

        self.assertEqual('b', e.options[0].name)
