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

from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1.loading._plugins.identity import base


class GenericBaseLoader(base.BaseIdentityLoader):

    def get_options(self):
        options = super(GenericBaseLoader, self).get_options()

        options.extend([
            loading.Opt('domain-id', help='Domain ID to scope to'),
            loading.Opt('domain-name', help='Domain name to scope to'),
            loading.Opt('tenant-id', help='Tenant ID to scope to'),
            loading.Opt('tenant-name', help='Tenant name to scope to'),
            loading.Opt('project-id', help='Project ID to scope to'),
            loading.Opt('project-name', help='Project name to scope to'),
            loading.Opt('project-domain-id',
                        help='Domain ID containing project'),
            loading.Opt('project-domain-name',
                        help='Domain name containing project'),
            loading.Opt('trust-id', help='Trust ID'),
        ])

        return options


class Token(GenericBaseLoader):

    @property
    def plugin_class(self):
        return identity.Token

    def get_options(self):
        options = super(Token, self).get_options()

        options.extend([
            loading.Opt('token', help='Token to authenticate with'),
        ])

        return options


class Password(GenericBaseLoader):

    @property
    def plugin_class(self):
        return identity.Password

    def get_options(cls):
        options = super(Password, cls).get_options()
        options.extend([
            loading.Opt('user-id', help='User id'),
            loading.Opt('user-name',
                        dest='username',
                        help='Username',
                        deprecated=[loading.Opt('username')]),
            loading.Opt('user-domain-id', help="User's domain id"),
            loading.Opt('user-domain-name', help="User's domain name"),
            loading.Opt('password', help="User's password"),
        ])
        return options
