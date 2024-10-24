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

from keystoneauth1 import discover
from keystoneauth1 import plugin

if ty.TYPE_CHECKING:
    from keystoneauth1.access import access
    from keystoneauth1 import session as ks_session


class Token(plugin.BaseAuthPlugin):
    """A provider that will always use the given token and endpoint.

    This is really only useful for testing and in certain CLI cases where you
    have a known endpoint and admin token that you want to use.
    """

    def __init__(self, endpoint: ty.Optional[str], token: ty.Optional[str]):
        super().__init__()
        # NOTE(jamielennox): endpoint is reserved for when plugins
        # can be used to provide that information
        self.endpoint = endpoint
        self.token = token

    def get_token(self, session: 'ks_session.Session') -> ty.Optional[str]:
        return self.token

    def get_endpoint_data(
        self,
        session: 'ks_session.Session',
        *,
        endpoint_override: ty.Optional[str] = None,
        discover_versions: bool = True,
        **kwargs: ty.Any,
    ) -> ty.Optional[discover.EndpointData]:
        """Return a valid endpoint data for a the service.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session
        :param str endpoint_override: URL to use for version discovery other
                                      than the endpoint stored in the plugin.
                                      (optional, defaults to None)
        :param bool discover_versions: Whether to get version metadata from
                                       the version discovery document even
                                       if it major api version info can be
                                       inferred from the url.
                                       (optional, defaults to True)
        :param kwargs: Ignored.

        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.

        :return: Valid EndpointData or None if not available.
        :rtype: `keystoneauth1.discover.EndpointData` or None
        """
        return super().get_endpoint_data(
            session,
            endpoint_override=endpoint_override or self.endpoint,
            discover_versions=discover_versions,
            **kwargs,
        )

    def get_endpoint(
        self, session: 'ks_session.Session', **kwargs: ty.Any
    ) -> ty.Optional[str]:
        """Return the supplied endpoint.

        Using this plugin the same endpoint is returned regardless of the
        parameters passed to the plugin.
        """
        return self.endpoint

    def get_auth_ref(
        self, session: 'ks_session.Session'
    ) -> ty.Optional['access.AccessInfo']:
        """Return the authentication reference of an auth plugin.

        :param session: A session object to be used for communication
        :type session: keystoneauth1.session.session
        """
        # token plugin does not have an auth ref, because it's a
        # "static" authentication using a pre-existing token.
        return None
