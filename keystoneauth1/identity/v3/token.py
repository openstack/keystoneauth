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

from keystoneauth1.identity.v3 import base
from keystoneauth1 import session as ks_session


__all__ = ('TokenMethod', 'Token')


class TokenMethod(base.AuthMethod):
    """Construct an Auth plugin to fetch a token from a token.

    :param string token: Token for authentication.
    """

    token: str

    def __init__(self, *, token: str) -> None:
        self.token = token

    def get_auth_data(
        self,
        session: ks_session.Session,
        auth: base.Auth,
        headers: dict[str, str],
        request_kwargs: dict[str, object],
    ) -> ty.Union[tuple[None, None], tuple[str, ty.Mapping[str, object]]]:
        headers['X-Auth-Token'] = self.token
        return 'token', {'id': self.token}

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        return {'token_token': self.token}


class Token(base.Auth):
    """A plugin for authenticating with an existing Token.

    :param string auth_url: Identity service endpoint for authentication.
    :param string token: Token for authentication.
    :param string trust_id: Trust ID for trust scoping.
    :param string domain_id: Domain ID for domain scoping.
    :param string domain_name: Domain name for domain scoping.
    :param string project_id: Project ID for project scoping.
    :param string project_name: Project name for project scoping.
    :param string project_domain_id: Project's domain ID for project.
    :param string project_domain_name: Project's domain name for project.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True
    """

    _auth_method_class = TokenMethod

    def __init__(
        self,
        auth_url: str,
        token: str,
        *,
        unscoped: bool = False,
        trust_id: ty.Optional[str] = None,
        system_scope: ty.Optional[str] = None,
        domain_id: ty.Optional[str] = None,
        domain_name: ty.Optional[str] = None,
        project_id: ty.Optional[str] = None,
        project_name: ty.Optional[str] = None,
        project_domain_id: ty.Optional[str] = None,
        project_domain_name: ty.Optional[str] = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
    ) -> None:
        method = self._auth_method_class(token=token)
        super().__init__(
            auth_url,
            [method],
            unscoped=unscoped,
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
