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

from keystoneauth1 import access
from keystoneauth1.identity.v3 import base
from keystoneauth1.identity.v3 import token
from keystoneauth1 import session as ks_session

__all__ = ('FederationBaseAuth',)


class _Rescoped(base.BaseAuth, metaclass=abc.ABCMeta):
    """A plugin that is always going to go through a rescope process.

    The original keystone plugins could simply pass a project or domain to
    along with the credentials and get a scoped token. For federation, K2K and
    newer mechanisms we always get an unscoped token first and then rescope.

    This is currently not public as it's generally an abstraction of a flow
    used by plugins within keystoneauth1.

    It also cannot go in base as it depends on token.Token for rescoping which
    would create a circular dependency.
    """

    rescoping_plugin = token.Token

    def get_auth_ref(self, session: ks_session.Session) -> access.AccessInfoV3:
        """Authenticate retrieve token information.

        This is a multi-step process where a client does federated authn
        receives an unscoped token.

        If an unscoped token is successfully received and scoping information
        is present then the token is rescoped to that target.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a token data representation
        :rtype: :py:class:`keystoneauth1.access.AccessInfo`

        """
        auth_ref = self.get_unscoped_auth_ref(session)

        # narrow type
        assert auth_ref.auth_token is not None  # nosec B101

        if any(
            [
                self.trust_id,
                self.domain_id,
                self.domain_name,
                self.project_id,
                self.project_name,
                self.project_domain_id,
                self.project_domain_name,
            ]
        ):
            token_plugin = self.rescoping_plugin(
                self.auth_url,
                token=auth_ref.auth_token,
                trust_id=self.trust_id,
                domain_id=self.domain_id,
                domain_name=self.domain_name,
                project_id=self.project_id,
                project_name=self.project_name,
                project_domain_id=self.project_domain_id,
                project_domain_name=self.project_domain_name,
            )

            auth_ref = token_plugin.get_auth_ref(session)

        return auth_ref

    @abc.abstractmethod
    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Fetch unscoped federated token."""


class FederationBaseAuth(_Rescoped):
    """Federation authentication plugin.

    :param auth_url: URL of the Identity Service
    :type auth_url: string
    :param identity_provider: name of the Identity Provider the client
                              will authenticate against. This parameter
                              will be used to build a dynamic URL used to
                              obtain unscoped OpenStack token.
    :type identity_provider: string
    :param protocol: name of the protocol the client will authenticate
                     against.
    :type protocol: string

    """

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
    ):
        super().__init__(
            auth_url=auth_url,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
        )
        self.identity_provider = identity_provider
        self.protocol = protocol

    @property
    def federated_token_url(self) -> str:
        """Full URL where authorization data is sent."""
        host = self.auth_url.rstrip('/')
        if not host.endswith('v3'):
            host += '/v3'
        values = {
            'host': host,
            'identity_provider': self.identity_provider,
            'protocol': self.protocol,
        }
        url = (
            "%(host)s/OS-FEDERATION/identity_providers/"
            "%(identity_provider)s/protocols/%(protocol)s/auth"
        )
        url = url % values

        return url
