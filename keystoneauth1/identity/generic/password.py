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


class Password(base.BaseGenericPlugin):
    """A common user/password authentication plugin.

    :param string username: Username for authentication.
    :param string user_id: User ID for authentication.
    :param string password: Password for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.
    """

    def __init__(
        self,
        auth_url: str,
        username: ty.Optional[str] = None,
        user_id: ty.Optional[str] = None,
        password: ty.Optional[str] = None,
        user_domain_id: ty.Optional[str] = None,
        user_domain_name: ty.Optional[str] = None,
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

        self._username = username
        self._user_id = user_id
        self._password = password
        self._user_domain_id = user_domain_id
        self._user_domain_name = user_domain_name

    def create_plugin(
        self,
        session: ks_session.Session,
        version: discover._PARSED_VERSION_T,
        url: str,
        raw_status: ty.Optional[str] = None,
    ) -> ty.Union[None, v2.Password, v3.Password]:
        if discover.version_match((2,), version):
            if self._user_domain_id or self._user_domain_name:
                # TODO(stephenfin): Shouldn't this be an error?
                return None

            if self._password is None:
                # FIXME(stephenfin): It would be better is password was a
                # non-optional paramter to this plugin but that requires
                # changing the __init__ signature
                raise Exception('password is a required attribute')

            return v2.Password(
                auth_url=url,
                user_id=self._user_id,
                username=self._username,
                password=self._password,
                trust_id=self._trust_id,
                tenant_id=self._project_id,
                tenant_name=self._project_name,
                reauthenticate=self.reauthenticate,
            )

        elif discover.version_match((3,), version):
            if self._password is None:
                # FIXME(stephenfin): It would be better is password was a
                # non-optional paramter to this plugin but that requires
                # changing the __init__ signature
                raise Exception('password is a required attribute')

            u_domain_id = self._user_domain_id or self._default_domain_id
            u_domain_name = self._user_domain_name or self._default_domain_name

            return v3.Password(
                auth_url=url,
                user_id=self._user_id,
                username=self._username,
                user_domain_id=u_domain_id,
                user_domain_name=u_domain_name,
                password=self._password,
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

    @property
    def user_domain_id(self) -> ty.Optional[str]:
        return self._user_domain_id or self._default_domain_id

    @user_domain_id.setter
    def user_domain_id(self, value: str) -> None:
        self._user_domain_id = value

    @property
    def user_domain_name(self) -> ty.Optional[str]:
        return self._user_domain_name or self._default_domain_name

    @user_domain_name.setter
    def user_domain_name(self, value: str) -> None:
        self._user_domain_name = value

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
            'username': self._username,
            'user_id': self._user_id,
            'password': self._password,
            'user_domain_id': self.user_domain_id,
            'user_domain_name': self.user_domain_name,
        }
