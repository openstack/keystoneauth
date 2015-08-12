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


class BaseV3Loader(base.BaseIdentityLoader):

    def get_options(self):
        options = super(BaseV3Loader, self).get_options()

        options.extend([
            cfg.StrOpt('domain-id', help='Domain ID to scope to'),
            cfg.StrOpt('domain-name', help='Domain name to scope to'),
            cfg.StrOpt('project-id', help='Project ID to scope to'),
            cfg.StrOpt('project-name', help='Project name to scope to'),
            cfg.StrOpt('project-domain-id',
                       help='Domain ID containing project'),
            cfg.StrOpt('project-domain-name',
                       help='Domain name containing project'),
            cfg.StrOpt('trust-id', help='Trust ID'),
        ])

        return options


class Password(BaseV3Loader):

    @property
    def plugin_class(self):
        return identity.V3Password

    def get_options(self):
        options = super(Password, self).get_options()

        options.extend([
            cfg.StrOpt('user-id', help='User ID'),
            cfg.StrOpt('user-name',
                       dest='username',
                       help='Username',
                       deprecated_name='username'),
            cfg.StrOpt('user-domain-id', help="User's domain id"),
            cfg.StrOpt('user-domain-name', help="User's domain name"),
            cfg.StrOpt('password', secret=True, help="User's password"),
        ])

        return options


class Token(BaseV3Loader):

    @property
    def plugin_class(self):
        return identity.Token

    def get_options(self):
        options = super(Token, self).get_options()

        options.extend([
            cfg.StrOpt('token',
                       secret=True,
                       help='Token to authenticate with'),
        ])

        return options


class FederatedBase(BaseV3Loader):

    def get_options(self):
        options = super(FederatedBase, self).get_options()

        options.extend([
            cfg.StrOpt('identity-provider',
                       help="Identity Provider's name"),
            cfg.StrOpt('protocol',
                       help='Protocol for federated plugin'),
        ])

        return options
