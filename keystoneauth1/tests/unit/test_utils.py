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

from keystoneauth1 import _utils


class UtilsTests(testtools.TestCase):
    def test_get_logger(self):
        self.assertEqual(
            'keystoneauth.tests.unit.test_utils',
            _utils.get_logger(__name__).name,
        )

    def test_mask_sensitive_data_nested(self):
        data = {
            'driver': 'pxe_ipmitool',
            'driver_info': {'ipmi_password': 'a12345'},
        }
        masked = _utils.mask_sensitive_data(data)
        self.assertEqual(masked['driver'], 'pxe_ipmitool')
        self.assertEqual(masked['driver_info']['ipmi_password'], '***')

    def test_mask_sensitive_string_json(self):
        payload = (
            '{"driver": "pxe_ipmitool", '
            '"driver_info": {"ipmi_password": "a12345"}}'
        )
        masked = _utils.mask_sensitive_string(payload)
        self.assertIn('"ipmi_password": "***"', masked)
        self.assertNotIn('a12345', masked)

    def test_mask_sensitive_string_non_json(self):
        data = 'BODYDATA'
        self.assertEqual(data, _utils.mask_sensitive_string(data))
