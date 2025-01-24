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
from keystoneauth1.identity.generic import base
from keystoneauth1.identity import v2
from keystoneauth1.identity import v3
from keystoneauth1 import session as ks_session


class Token(base.BaseGenericPlugin):
    """Generic token auth plugin.

    :param string token: Token for authentication.
    """

    def __init__(
        self,
        auth_url: str,
        token: str,
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
        super().__init__(
            auth_url=auth_url,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            domain_id=domain_id,
            domain_name=domain_name,
            system_scope=system_scope,
            trust_id=trust_id,
            default_domain_id=default_domain_id,
            default_domain_name=default_domain_name,
            reauthenticate=reauthenticate,
        )

        self._token = token

    def create_plugin(
        self,
        session: ks_session.Session,
        version: discover._PARSED_VERSION_T,
        url: str,
        raw_status: ty.Optional[str] = None,
    ) -> ty.Union[None, v2.Token, v3.Token]:
        if discover.version_match((2,), version):
            return v2.Token(
                url,
                self._token,
                trust_id=self._trust_id,
                tenant_id=self._project_id,
                tenant_name=self._project_name,
                reauthenticate=self.reauthenticate,
            )

        if discover.version_match((3,), version):
            return v3.Token(
                url,
                self._token,
                trust_id=self._trust_id,
                system_scope=self._system_scope,
                project_id=self._project_id,
                project_name=self._project_name,
                project_domain_id=self.project_domain_id,
                project_domain_name=self.project_domain_name,
                domain_id=self._domain_id,
                domain_name=self._domain_name,
                reauthenticate=self.reauthenticate,
            )

        return None

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        return {
            'auth_url': self.auth_url,
            'project_id': self._project_id,
            'project_name': self._project_name,
            'project_domain_id': self.project_domain_id,
            'project_domain_name': self.project_domain_name,
            'domain_id': self._domain_id,
            'domain_name': self._domain_name,
            'trust_id': self._trust_id,
            'token': self._token,
        }
