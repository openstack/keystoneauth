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

import abc
import typing as ty
import urllib.parse

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import discover
from keystoneauth1 import exceptions
from keystoneauth1.identity import base
from keystoneauth1.identity import v2
from keystoneauth1.identity.v3 import base as v3
from keystoneauth1 import session as ks_session


LOG = utils.get_logger(__name__)


class BaseGenericPlugin(base.BaseIdentityPlugin, metaclass=abc.ABCMeta):
    """An identity plugin that is not version dependent.

    Internally we will construct a version dependent plugin with the resolved
    URL and then proxy all calls from the base plugin to the versioned one.
    """

    auth_url: str

    def __init__(
        self,
        auth_url: ty.Optional[str] = None,
        *,
        tenant_id: ty.Optional[str] = None,
        tenant_name: ty.Optional[str] = None,
        project_id: ty.Optional[str] = None,
        project_name: ty.Optional[str] = None,
        project_domain_id: ty.Optional[str] = None,
        project_domain_name: ty.Optional[str] = None,
        domain_id: ty.Optional[str] = None,
        domain_name: ty.Optional[str] = None,
        system_scope: ty.Optional[str] = None,
        trust_id: ty.Optional[str] = None,
        default_domain_id: ty.Optional[str] = None,
        default_domain_name: ty.Optional[str] = None,
        reauthenticate: bool = True,
    ):
        super().__init__(auth_url=auth_url, reauthenticate=reauthenticate)

        self._project_id = project_id or tenant_id
        self._project_name = project_name or tenant_name
        self._project_domain_id = project_domain_id
        self._project_domain_name = project_domain_name
        self._domain_id = domain_id
        self._domain_name = domain_name
        self._system_scope = system_scope
        self._trust_id = trust_id
        self._default_domain_id = default_domain_id
        self._default_domain_name = default_domain_name

        self._plugin: ty.Union[v2.Auth, v3.Auth, None] = None

    @abc.abstractmethod
    def create_plugin(
        self,
        session: ks_session.Session,
        version: discover._PARSED_VERSION_T,
        url: str,
        raw_status: ty.Optional[str] = None,
    ) -> ty.Union[None, v2.Auth, v3.Auth]:
        """Create a plugin from the given parameters.

        This function will be called multiple times with the version and url
        of a potential endpoint. If a plugin can be constructed that fits the
        params then it should return it. If not return None and then another
        call will be made with other available URLs.

        :param session: A session object.
        :type session: keystoneauth1.session.Session
        :param tuple version: A tuple of the API version at the URL.
        :param str url: The base URL for this version.
        :param str raw_status: The status that was in the discovery field.

        :returns: A plugin that can match the parameters or None if nothing.
        """
        return None

    @property
    def _has_domain_scope(self) -> bool:
        """Are there domain parameters.

        Domain parameters are v3 only so returns if any are set.

        :returns: True if a domain parameter is set, false otherwise.
        """
        return any(
            [
                self._domain_id,
                self._domain_name,
                self._project_domain_id,
                self._project_domain_name,
            ]
        )

    @property
    def project_domain_id(self) -> ty.Optional[str]:
        return self._project_domain_id or self._default_domain_id

    @project_domain_id.setter
    def project_domain_id(self, value: ty.Optional[str]) -> None:
        self._project_domain_id = value

    @property
    def project_domain_name(self) -> ty.Optional[str]:
        return self._project_domain_name or self._default_domain_name

    @project_domain_name.setter
    def project_domain_name(self, value: ty.Optional[str]) -> None:
        self._project_domain_name = value

    def _do_create_plugin(
        self, session: ks_session.Session
    ) -> ty.Union[v2.Auth, v3.Auth]:
        plugin = None

        try:
            disc = self.get_discovery(
                session, self.auth_url, authenticated=False
            )
        except (
            exceptions.DiscoveryFailure,
            exceptions.HttpError,
            exceptions.SSLError,
            exceptions.ConnectionError,
        ) as e:
            LOG.warning(
                'Failed to discover available identity versions when '
                'contacting %s. Attempting to parse version from URL.',
                self.auth_url,
            )

            url_parts = urllib.parse.urlparse(self.auth_url)
            path = url_parts.path.lower()

            if path.startswith('/v2.0'):
                if self._has_domain_scope:
                    raise exceptions.DiscoveryFailure(
                        'Cannot use v2 authentication with domain scope'
                    )
                plugin = self.create_plugin(session, (2, 0), self.auth_url)
            elif path.startswith('/v3'):
                plugin = self.create_plugin(session, (3, 0), self.auth_url)
            else:
                raise exceptions.DiscoveryFailure(
                    'Could not find versioned identity endpoints when '
                    'attempting to authenticate. Please check that your '
                    f'auth_url is correct. {e}'
                )

        else:
            # NOTE(jamielennox): version_data is always in oldest to newest
            # order. This is fine normally because we explicitly skip v2 below
            # if there is domain data present. With default_domain params
            # though we want a v3 plugin if available and fall back to v2 so we
            # have to process in reverse order.
            # FIXME(jamielennox): if we ever go for another version we should
            # reverse this logic as we always want to favour the newest
            # available version.
            reverse = self._default_domain_id or self._default_domain_name
            disc_data = disc.version_data(reverse=bool(reverse))

            v2_with_domain_scope = False
            for data in disc_data:
                version = data['version']

                if (
                    discover.version_match((2,), version)
                    and self._has_domain_scope
                ):
                    # NOTE(jamielennox): if there are domain parameters there
                    # is no point even trying against v2 APIs.
                    v2_with_domain_scope = True
                    continue

                plugin = self.create_plugin(
                    session,
                    version,
                    data['url'],
                    raw_status=data['raw_status'],
                )

                if plugin:
                    break
            if not plugin and v2_with_domain_scope:
                raise exceptions.DiscoveryFailure(
                    'Cannot use v2 authentication with domain scope'
                )

        if plugin:
            return plugin

        # so there were no URLs that i could use for auth of any version.
        raise exceptions.DiscoveryFailure(
            'Could not find versioned identity endpoints when attempting '
            'to authenticate. Please check that your auth_url is correct.'
        )

    def get_auth_ref(self, session: ks_session.Session) -> access.AccessInfo:
        if self._plugin:
            plugin = self._plugin
        else:
            plugin = self._do_create_plugin(session)
            self._plugin = plugin

        return plugin.get_auth_ref(session)

    @abc.abstractmethod
    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        raise NotImplementedError()
