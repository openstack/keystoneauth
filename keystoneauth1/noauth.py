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

from keystoneauth1 import plugin

if ty.TYPE_CHECKING:
    from keystoneauth1 import session as ks_session


class NoAuth(plugin.FixedEndpointPlugin):
    """A provider that will always use no auth.

    This is useful to unify session/adapter loading for services
    that might be deployed in standalone/noauth mode.
    """

    def get_token(self, session: 'ks_session.Session') -> str | None:
        return 'notused'
