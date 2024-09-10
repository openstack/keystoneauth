# Copyright 2018 SUSE Linux GmbH
#
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


__all__ = ('ApplicationCredentialMethod', 'ApplicationCredential')


class ApplicationCredentialMethod(base.AuthMethod):
    """Construct a User/Passcode based authentication method.

    :param string application_credential_secret: Application credential secret.
    :param string application_credential_id: Application credential id.
    :param string application_credential_name: The name of the application
                                               credential, if an ID is not
                                               provided.
    :param string username: Username for authentication, if an application
                            credential ID is not provided.
    :param string user_id: User ID for authentication, if an application
                           credential ID is not provided.
    :param string user_domain_id: User's domain ID for authentication, if an
                                  application credential ID is not provided.
    :param string user_domain_name: User's domain name for authentication, if
                                    an application credential ID is not
                                    provided.
    """

    application_credential_secret: str
    application_credential_id: ty.Optional[str] = None
    application_credential_name: ty.Optional[str] = None
    user_id: ty.Optional[str] = None
    username: ty.Optional[str] = None
    user_domain_id: ty.Optional[str] = None
    user_domain_name: ty.Optional[str] = None

    def __init__(
        self,
        *,
        application_credential_secret: str,
        application_credential_id: ty.Optional[str] = None,
        application_credential_name: ty.Optional[str] = None,
        user_id: ty.Optional[str] = None,
        username: ty.Optional[str] = None,
        user_domain_id: ty.Optional[str] = None,
        user_domain_name: ty.Optional[str] = None,
    ) -> None:
        self.application_credential_secret = application_credential_secret
        self.application_credential_id = application_credential_id
        self.application_credential_name = application_credential_name
        self.user_id = user_id
        self.username = username
        self.user_domain_id = user_domain_id
        self.user_domain_name = user_domain_name

    def get_auth_data(
        self,
        session: ks_session.Session,
        auth: base.Auth,
        headers: dict[str, str],
        request_kwargs: dict[str, object],
    ) -> ty.Union[tuple[None, None], tuple[str, ty.Mapping[str, object]]]:
        auth_data: dict[str, ty.Any] = {
            'secret': self.application_credential_secret
        }

        if self.application_credential_id:
            auth_data['id'] = self.application_credential_id
        else:
            auth_data['name'] = self.application_credential_name
            auth_data['user'] = {}
            if self.user_id:
                auth_data['user']['id'] = self.user_id
            elif self.username:
                auth_data['user']['name'] = self.username

                if self.user_domain_id:
                    auth_data['user']['domain'] = {'id': self.user_domain_id}
                elif self.user_domain_name:
                    auth_data['user']['domain'] = {
                        'name': self.user_domain_name
                    }

        return 'application_credential', auth_data

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        return {
            'application_credential_application_credential_secret': self.application_credential_secret,
            'application_credential_application_credential_id': self.application_credential_id,
            'application_credential_application_credential_name': self.application_credential_name,
            'application_credential_user_id': self.user_id,
            'application_credential_username': self.username,
            'application_credential_user_domain_id': self.user_domain_id,
            'application_credential_user_domain_name': self.user_domain_name,
        }


class ApplicationCredential(base.Auth):
    """A plugin for authenticating with an application credential.

    :param string auth_url: Identity service endpoint for authentication.
    :param string application_credential_secret: Application credential secret.
    :param string application_credential_id: Application credential ID.
    :param string application_credential_name: Application credential name.
    :param string username: Username for authentication.
    :param string user_id: User ID for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True
    """

    _auth_method_class = ApplicationCredentialMethod

    def __init__(
        self,
        auth_url: str,
        application_credential_secret: str,
        application_credential_id: ty.Optional[str] = None,
        application_credential_name: ty.Optional[str] = None,
        user_id: ty.Optional[str] = None,
        username: ty.Optional[str] = None,
        user_domain_id: ty.Optional[str] = None,
        user_domain_name: ty.Optional[str] = None,
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
        method = self._auth_method_class(
            application_credential_secret=application_credential_secret,
            application_credential_id=application_credential_id,
            application_credential_name=application_credential_name,
            user_id=user_id,
            username=username,
            user_domain_id=user_domain_id,
            user_domain_name=user_domain_name,
        )
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
