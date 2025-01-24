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

from keystoneauth1 import loading
from keystoneauth1.loading import opts
from keystoneauth1 import noauth


class NoAuth(loading.BaseLoader[noauth.NoAuth]):
    """Use no tokens to perform requests.

    This can be used to instantiate clients for services deployed in
    noauth/standalone mode.

    There is no fetching a service catalog or determining scope information
    and so it cannot be used by clients that expect to use this scope
    information.

    """

    @property
    def plugin_class(self) -> ty.Type[noauth.NoAuth]:
        return noauth.NoAuth

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'endpoint', help='The endpoint that will always be used'
                )
            ]
        )

        return options
