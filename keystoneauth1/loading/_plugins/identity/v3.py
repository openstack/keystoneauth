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

from keystoneauth1 import exceptions
from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1.loading._plugins.identity import base


class BaseV3Loader(base.BaseIdentityLoader):

    def get_options(self):
        options = super(BaseV3Loader, self).get_options()

        options.extend([
            loading.Opt('domain-id', help='Domain ID to scope to'),
            loading.Opt('domain-name', help='Domain name to scope to'),
            loading.Opt('project-id', help='Project ID to scope to'),
            loading.Opt('project-name', help='Project name to scope to'),
            loading.Opt('project-domain-id',
                        help='Domain ID containing project'),
            loading.Opt('project-domain-name',
                        help='Domain name containing project'),
            loading.Opt('trust-id', help='Trust ID'),
        ])

        return options

    def load_from_options(self, **kwargs):
        if (kwargs.get('project_name') and
                not (kwargs.get('project_domain_name') or
                     kwargs.get('project_domain_id'))):
            m = "You have provided a project_name. In the V3 identity API a " \
                "project_name is only unique within a domain so you must " \
                "also provide either a project_domain_id or " \
                "project_domain_name."
            raise exceptions.OptionError(m)

        return super(BaseV3Loader, self).load_from_options(**kwargs)


class Password(BaseV3Loader):

    @property
    def plugin_class(self):
        return identity.V3Password

    def get_options(self):
        options = super(Password, self).get_options()

        options.extend([
            loading.Opt('user-id', help='User ID'),
            loading.Opt('user-name',
                        dest='username',
                        help='Username',
                        deprecated=[loading.Opt('username')]),
            loading.Opt('user-domain-id', help="User's domain id"),
            loading.Opt('user-domain-name', help="User's domain name"),
            loading.Opt('password', secret=True, help="User's password"),
        ])

        return options

    def load_from_options(self, **kwargs):
        if (kwargs.get('username') and
                not (kwargs.get('user_domain_name') or
                     kwargs.get('user_domain_id'))):
            m = "You have provided a username. In the V3 identity API a " \
                "username is only unique within a domain so you must " \
                "also provide either a user_domain_id or user_domain_name."
            raise exceptions.OptionError(m)

        return super(Password, self).load_from_options(**kwargs)


class Token(BaseV3Loader):

    @property
    def plugin_class(self):
        return identity.V3Token

    def get_options(self):
        options = super(Token, self).get_options()

        options.extend([
            loading.Opt('token',
                        secret=True,
                        help='Token to authenticate with'),
        ])

        return options


class FederatedBase(BaseV3Loader):

    def get_options(self):
        options = super(FederatedBase, self).get_options()

        options.extend([
            loading.Opt('identity-provider',
                        help="Identity Provider's name"),
            loading.Opt('protocol',
                        help='Protocol for federated plugin'),
        ])

        return options
