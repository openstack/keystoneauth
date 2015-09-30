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


class _OpenIDConnectBase(FederatedBase):

    def get_options(self):
        options = super(_OpenIDConnectBase, self).get_options()

        options.extend([
            loading.Opt('client-id', help='OAuth 2.0 Client ID'),
            loading.Opt('client-secret', help='OAuth 2.0 Client Secret'),
            loading.Opt('access-token-endpoint',
                        help='OpenID Connect Provider Token Endpoint'),
            loading.Opt('access-token-type',
                        help='OAuth 2.0 Authorization Server Introspection '
                             'token type, it is used to decide which type '
                             'of token will be used when processing token '
                             'introspection. Valid values are: '
                             '"access_token" or "id_token"'),
        ])

        return options


class OpenIDConnectPassword(_OpenIDConnectBase):

    @property
    def plugin_class(self):
        return identity.V3OidcPassword

    def get_options(self):
        options = super(OpenIDConnectPassword, self).get_options()

        options.extend([
            loading.Opt('username', help='Username'),
            loading.Opt('password', help='Password'),
            loading.Opt('openid-scope', default="profile",
                        help='OpenID Connect scope that is requested from OP')
        ])

        return options


class OpenIDConnectAuthorizationCode(_OpenIDConnectBase):

    @property
    def plugin_class(self):
        return identity.V3OidcAuthorizationCode

    def get_options(self):
        options = super(OpenIDConnectAuthorizationCode, self).get_options()

        options.extend([
            loading.Opt('redirect-uri', help='OpenID Connect Redirect URL'),
            loading.Opt('authorization-code',
                        help='OAuth 2.0 Authorization Code'),
        ])

        return options
