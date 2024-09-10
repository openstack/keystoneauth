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

import copy
import typing as ty

from keystoneauth1.identity.v3 import base
from keystoneauth1 import session as ks_session


__all__ = ('TOTPMethod', 'TOTP')


class TOTPMethod(base.AuthMethod):
    """Construct a User/Passcode based authentication method.

    :param string passcode: TOTP passcode for authentication.
    :param string username: Username for authentication.
    :param string user_id: User ID for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.
    """

    user_id: str
    username: str
    user_domain_id: str
    user_domain_name: str
    passcode: str

    _method_parameters = [
        'user_id',
        'username',
        'user_domain_id',
        'user_domain_name',
        'passcode',
    ]

    # TODO(stephenfin): Deprecate and remove unused kwargs
    def get_auth_data(
        self,
        session: ks_session.Session,
        auth: base.Auth,
        headers: ty.Dict[str, str],
        request_kwargs: ty.Dict[str, object],
        **kwargs: ty.Any,
    ) -> ty.Union[
        ty.Tuple[None, None], ty.Tuple[str, ty.Mapping[str, object]]
    ]:
        user: ty.Dict[str, ty.Any] = {'passcode': self.passcode}

        if self.user_id:
            user['id'] = self.user_id
        elif self.username:
            user['name'] = self.username

            if self.user_domain_id:
                user['domain'] = {'id': self.user_domain_id}
            elif self.user_domain_name:
                user['domain'] = {'name': self.user_domain_name}

        return 'totp', {'user': user}

    def get_cache_id_elements(self) -> ty.Dict[str, ty.Optional[str]]:
        # NOTE(gyee): passcode is not static so we cannot use it as part of
        # the key in caching.
        params = copy.copy(self._method_parameters)
        params.remove('passcode')
        return {f'totp_{p}': getattr(self, p) for p in self._method_parameters}


class TOTP(base.AuthConstructor):
    """A plugin for authenticating with a username and TOTP passcode.

    :param string auth_url: Identity service endpoint for authentication.
    :param string passcode: TOTP passcode for authentication.
    :param string username: Username for authentication.
    :param string user_id: User ID for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.
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

    _auth_method_class = TOTPMethod
