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
from keystoneauth1.loading import opts


class Token(loading.BaseGenericLoader[identity.Token]):
    """Given an existing token rescope it to another target.

    Use the Identity service's rescope mechanism to get a new token based upon
    an existing token. Because an auth plugin requires a service catalog and
    scope information it is often easier to fetch a new token based on an
    existing one than validate and reuse the one you already have.

    As a generic plugin this plugin is identity version independent and will
    discover available versions before use. This means it expects to be
    provided an unversioned URL to operate against.
    """

    @property
    def plugin_class(self) -> type[identity.Token]:
        return identity.Token

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'token', secret=True, help='Token to authenticate with'
                )
            ]
        )

        return options


class Password(loading.BaseGenericLoader[identity.Password]):
    """Authenticate with a username and password.

    Authenticate to the identity service using the provided username and
    password. This is the standard and most common form of authentication.

    As a generic plugin this plugin is identity version independent and will
    discover available versions before use. This means it expects to be
    provided an unversioned URL to operate against.
    """

    @property
    def plugin_class(self) -> type[identity.Password]:
        return identity.Password

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()
        options.extend(
            [
                loading.Opt('user-id', help='User id'),
                loading.Opt(
                    'username',
                    help='Username',
                    deprecated=[loading.Opt('user-name')],
                ),
                loading.Opt('user-domain-id', help="User's domain id"),
                loading.Opt('user-domain-name', help="User's domain name"),
                loading.Opt(
                    'password',
                    secret=True,
                    prompt='Password: ',
                    help="User's password",
                ),
            ]
        )
        return options
