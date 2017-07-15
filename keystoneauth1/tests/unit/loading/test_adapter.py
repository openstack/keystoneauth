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

from oslo_config import cfg
from oslo_config import fixture as config

from keystoneauth1 import loading
from keystoneauth1.tests.unit.loading import utils


class ConfLoadingTests(utils.TestCase):

    GROUP = 'adaptergroup'

    def setUp(self):
        super(ConfLoadingTests, self).setUp()

        self.conf_fx = self.useFixture(config.Config())
        loading.register_adapter_conf_options(self.conf_fx.conf, self.GROUP)

    def test_load(self):
        self.conf_fx.config(
            service_type='type', service_name='name', interface='iface',
            region_name='region', endpoint_override='endpoint',
            version='2.0', group=self.GROUP)
        adap = loading.load_adapter_from_conf_options(
            self.conf_fx.conf, self.GROUP, session='session', auth='auth')
        self.assertEqual('type', adap.service_type)
        self.assertEqual('name', adap.service_name)
        self.assertEqual('iface', adap.interface)
        self.assertEqual('region', adap.region_name)
        self.assertEqual('endpoint', adap.endpoint_override)
        self.assertEqual('session', adap.session)
        self.assertEqual('auth', adap.auth)
        self.assertEqual('2.0', adap.version)
        self.assertIsNone(adap.min_version)
        self.assertIsNone(adap.max_version)

    def test_load_version_range(self):
        self.conf_fx.config(
            service_type='type', service_name='name', interface='iface',
            region_name='region', endpoint_override='endpoint',
            min_version='2.0', max_version='3.0', group=self.GROUP)
        adap = loading.load_adapter_from_conf_options(
            self.conf_fx.conf, self.GROUP, session='session', auth='auth')
        self.assertEqual('type', adap.service_type)
        self.assertEqual('name', adap.service_name)
        self.assertEqual('iface', adap.interface)
        self.assertEqual('region', adap.region_name)
        self.assertEqual('endpoint', adap.endpoint_override)
        self.assertEqual('session', adap.session)
        self.assertEqual('auth', adap.auth)
        self.assertIsNone(adap.version)
        self.assertEqual('2.0', adap.min_version)
        self.assertEqual('3.0', adap.max_version)

    def test_load_bad_version(self):
        self.conf_fx.config(
            service_type='type', service_name='name', interface='iface',
            region_name='region', endpoint_override='endpoint',
            version='2.0', min_version='2.0', max_version='3.0',
            group=self.GROUP)

        self.assertRaises(
            TypeError,
            loading.load_adapter_from_conf_options,
            self.conf_fx.conf, self.GROUP, session='session', auth='auth')

    def test_get_conf_options(self):
        opts = loading.get_adapter_conf_options()
        for opt in opts:
            self.assertIsInstance(opt, cfg.StrOpt)
        self.assertEqual({'service-type', 'service-name', 'interface',
                          'region-name', 'endpoint-override', 'version',
                          'min-version', 'max-version'},
                         {opt.name for opt in opts})
