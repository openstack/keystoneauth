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

"""A wrapper plugin to send service tokens with requests."""

from typing import Any

from keystoneauth1 import discover
from keystoneauth1 import plugin
from keystoneauth1 import session as ks_session

SERVICE_AUTH_HEADER_NAME = 'X-Service-Token'

__all__ = ('ServiceTokenAuthWrapper',)


class ServiceTokenAuthWrapper(plugin.BaseAuthPlugin):
    """A wrapper plugin that sends both a user token and a service token.

    This plugin combines a primary user authentication plugin and a secondary
    service authentication plugin. On outgoing HTTP requests, it injects both
    the standard user token (via ``X-Auth-Token``) and a service token (via
    ``X-Service-Token``).

    All other operations (such as token retrieval, endpoint discovery, version
    negotiation, and project/user ID resolution) are delegated to the
    underlying ``user_auth`` plugin.

    :param user_auth: The primary authentication plugin representing the user.
    :param service_auth: The secondary authentication plugin representing the
        service account.
    """

    def __init__(
        self,
        user_auth: plugin.BaseAuthPlugin,
        service_auth: plugin.BaseAuthPlugin,
    ):
        super().__init__()
        self.user_auth = user_auth
        self.service_auth = service_auth

    def get_headers(
        self, session: ks_session.Session
    ) -> dict[str, str] | None:
        """Fetch current headers for a request.

        This calls :meth:`.get_headers` on ``user_auth`` and appends the
        service token retrieved from ``service_auth.get_token()`` under the
        ``X-Service-Token`` header name.
        """
        headers = self.user_auth.get_headers(session) or {}
        token = self.service_auth.get_token(session)
        if token:
            headers[SERVICE_AUTH_HEADER_NAME] = token

        return headers

    def invalidate(self) -> bool:
        """Invalidate the cache of both the user and service auth plugins.

        :returns: True if either plugin's cache was invalidated, False
            otherwise.
        """
        # NOTE(jamielennox): hmm, what to do here? Should we invalidate both
        # the service and user auth? Only one? There's no way to know what the
        # failure was to selectively invalidate.
        user = self.user_auth.invalidate()
        service = self.service_auth.invalidate()
        return user or service

    def get_connection_params(
        self, session: ks_session.Session
    ) -> plugin.ConnectionParams:
        """Return connection params from both plugins.

        Parameters from ``user_auth`` take priority over ``service_auth``
        parameters.
        """
        # NOTE(jamielennox): This is also a bit of a guess but unlikely to be a
        # problem in practice. We don't know how merging connection parameters
        # between these plugins will conflict - but there aren't many plugins
        # that set this anyway.
        # Take the service auth params first so that user auth params will be
        # given priority.
        params = self.service_auth.get_connection_params(session)
        params.update(self.user_auth.get_connection_params(session))
        return params

    # TODO(jamielennox): Everything below here is a generic wrapper that could
    # be extracted into a base wrapper class. We can do this as soon as there
    # is a need for it, but we may never actually need it.

    def get_token(self, session: ks_session.Session) -> str | None:
        return self.user_auth.get_token(session)

    def get_endpoint(
        self, session: ks_session.Session, **kwargs: Any
    ) -> str | None:
        return self.user_auth.get_endpoint(session, **kwargs)

    def get_endpoint_data(
        self,
        session: ks_session.Session,
        *,
        endpoint_override: str | None = None,
        discover_versions: bool = True,
        **kwargs: Any,
    ) -> discover.EndpointData | None:
        return self.user_auth.get_endpoint_data(
            session,
            endpoint_override=endpoint_override,
            discover_versions=discover_versions,
            **kwargs,
        )

    def get_api_major_version(
        self, session: ks_session.Session, **kwargs: Any
    ) -> tuple[int | float, ...] | None:
        return self.user_auth.get_api_major_version(session, **kwargs)

    def get_user_id(self, session: ks_session.Session) -> str | None:
        return self.user_auth.get_user_id(session)

    def get_project_id(self, session: ks_session.Session) -> str | None:
        return self.user_auth.get_project_id(session)

    def get_sp_auth_url(
        self, session: ks_session.Session, sp_id: str
    ) -> str | None:
        return self.user_auth.get_sp_auth_url(session, sp_id)

    def get_sp_url(
        self, session: ks_session.Session, sp_id: str
    ) -> str | None:
        return self.user_auth.get_sp_url(session, sp_id)
