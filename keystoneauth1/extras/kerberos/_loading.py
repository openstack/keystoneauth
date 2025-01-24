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

import typing as ty

from keystoneauth1 import exceptions
from keystoneauth1.extras import kerberos
from keystoneauth1 import loading
from keystoneauth1.loading import opts


class Kerberos(loading.BaseV3Loader[kerberos.Kerberos]):
    @property
    def plugin_class(self) -> ty.Type[kerberos.Kerberos]:
        return kerberos.Kerberos

    @property
    def available(self) -> bool:
        return kerberos.requests_kerberos is not None

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'mutual-auth',
                    required=False,
                    default='optional',
                    help='Configures Kerberos Mutual Authentication',
                )
            ]
        )

        return options

    def load_from_options(self, **kwargs: ty.Any) -> kerberos.Kerberos:
        if kwargs.get('mutual_auth'):
            value = kwargs['mutual_auth']
            if value.lower() not in ['required', 'optional', 'disabled']:
                m = (
                    'You need to provide a valid value for kerberos mutual '
                    'authentication. It can be one of the following: '
                    '(required, optional, disabled)'
                )
                raise exceptions.OptionError(m)

        return super().load_from_options(**kwargs)


class MappedKerberos(loading.BaseFederationLoader[kerberos.MappedKerberos]):
    @property
    def plugin_class(self) -> ty.Type[kerberos.MappedKerberos]:
        return kerberos.MappedKerberos

    @property
    def available(self) -> bool:
        return kerberos.requests_kerberos is not None

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'mutual-auth',
                    required=False,
                    default='optional',
                    help='Configures Kerberos Mutual Authentication',
                )
            ]
        )

        return options

    def load_from_options(self, **kwargs: ty.Any) -> kerberos.MappedKerberos:
        if kwargs.get('mutual_auth'):
            value = kwargs['mutual_auth']
            if value.lower() not in ['required', 'optional', 'disabled']:
                m = (
                    'You need to provide a valid value for kerberos mutual '
                    'authentication. It can be one of the following: '
                    '(required, optional, disabled)'
                )
                raise exceptions.OptionError(m)

        return super().load_from_options(**kwargs)
