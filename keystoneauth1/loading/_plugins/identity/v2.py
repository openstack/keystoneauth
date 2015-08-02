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

from keystoneauth1 import identity
from keystoneauth1.loading._plugins.identity import base


class BaseV2Loader(base.BaseIdentityLoader):

    def get_options(self):
        options = super(BaseV2Loader, self).get_options()

        options.extend([
            cfg.StrOpt('tenant-id', help='Tenant ID'),
            cfg.StrOpt('tenant-name', help='Tenant Name'),
            cfg.StrOpt('trust-id', help='Trust ID'),
        ])

        return options


class V2Token(BaseV2Loader):

    @property
    def plugin_class(self):
        return identity.V2Token

    def get_options(self):
        options = super(V2Token, self).get_options()

        options.extend([
            cfg.StrOpt('token', secret=True, help='Token'),
        ])

        return options


class V2Password(BaseV2Loader):

    @property
    def plugin_class(self):
        return identity.V2Password

    def get_options(self):
        options = super(V2Password, self).get_options()

        options.extend([
            cfg.StrOpt('user-name',
                       dest='username',
                       deprecated_name='username',
                       help='Username to login with'),
            cfg.StrOpt('user-id', help='User ID to longin with'),
            cfg.StrOpt('password', secret=True, help='Password to use'),
        ])

        return options
