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

import os
from unittest import mock

from keystoneauth1.loading import opts
from keystoneauth1.tests.unit.loading import utils


class OptTests(utils.TestCase):
    def test_argparse_args(self):
        opt = opts.Opt('auth-url')
        self.assertEqual(['--os-auth-url'], opt.argparse_args)

    def test_argparse_args_with_deprecations(self):
        opt = opts.Opt('username', deprecated=[opts.Opt('user-name')])
        self.assertEqual(
            ['--os-username', '--os-user-name'], opt.argparse_args
        )

    def test_argparse_envvars(self):
        opt = opts.Opt('auth-url')
        self.assertEqual(['OS_AUTH_URL'], opt.argparse_envvars)

    def test_argparse_envvars_with_deprecations(self):
        opt = opts.Opt('username', deprecated=[opts.Opt('user-name')])
        self.assertEqual(['OS_USERNAME', 'OS_USER_NAME'], opt.argparse_envvars)

    def test_argparse_default(self):
        opt = opts.Opt('auth-url')

        with mock.patch.dict(
            os.environ, {'OS_AUTH_URL': 'http://1.2.3.4/identity'}, clear=True
        ):
            self.assertEqual('http://1.2.3.4/identity', opt.argparse_default)

    def test_argparse_default_with_deprecations(self):
        opt = opts.Opt('username', deprecated=[opts.Opt('user-name')])

        with mock.patch.dict(
            os.environ, {'OS_USER_NAME': 'superuser'}, clear=True
        ):
            self.assertEqual('superuser', opt.argparse_default)
