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
import collections.abc
import enum
import typing as ty

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity import base
from keystoneauth1 import session as ks_session

_logger = utils.get_logger(__name__)


class Auth(base.BaseIdentityPlugin, metaclass=abc.ABCMeta):
    """Identity V2 Authentication Plugin.

    :param string auth_url: Identity service endpoint for authorization.
    :param string trust_id: Trust ID for trust scoping.
    :param string tenant_id: Tenant ID for project scoping.
    :param string tenant_name: Tenant name for project scoping.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True
    """

    auth_url: str

    def __init__(
        self,
        auth_url: str,
        *,
        trust_id: ty.Optional[str] = None,
        tenant_id: ty.Optional[str] = None,
        tenant_name: ty.Optional[str] = None,
        reauthenticate: bool = True,
    ):
        super().__init__(auth_url=auth_url, reauthenticate=reauthenticate)

        self.trust_id = trust_id
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name

    def get_auth_ref(self, session: ks_session.Session) -> access.AccessInfoV2:
        headers = {'Accept': 'application/json'}
        url = self.auth_url.rstrip('/') + '/tokens'
        params = {'auth': self.get_auth_data(headers)}

        if self.tenant_id:
            params['auth']['tenantId'] = self.tenant_id
        elif self.tenant_name:
            params['auth']['tenantName'] = self.tenant_name
        if self.trust_id:
            params['auth']['trust_id'] = self.trust_id

        _logger.debug('Making authentication request to %s', url)
        resp = session.post(
            url, json=params, headers=headers, authenticated=False, log=False
        )

        try:
            resp_data = resp.json()
        except ValueError:
            raise exceptions.InvalidResponse(response=resp)

        if 'access' not in resp_data:
            raise exceptions.InvalidResponse(response=resp)

        return access.AccessInfoV2(resp_data)

    @abc.abstractmethod
    def get_auth_data(
        self,
        headers: ty.Optional[collections.abc.MutableMapping[str, str]] = None,
    ) -> dict[str, object]:
        """Return the authentication section of an auth plugin.

        :param dict headers: The headers that will be sent with the auth
                             request if a plugin needs to add to them.
        :return: A dict of authentication data for the auth type.
        :rtype: dict
        """

    @property
    def has_scope_parameters(self) -> bool:
        """Return true if parameters can be used to create a scoped token."""
        return bool(self.tenant_id or self.tenant_name or self.trust_id)


# https://peps.python.org/pep-0484/#support-for-singleton-types-in-unions
class Unset(enum.Enum):
    token = 0


_unset = Unset.token


class Password(Auth):
    """A plugin for authenticating with a username and password.

    A username or user_id must be provided.

    :param string auth_url: Identity service endpoint for authorization.
    :param string username: Username for authentication.
    :param string password: Password for authentication.
    :param string user_id: User ID for authentication.
    :param string trust_id: Trust ID for trust scoping.
    :param string tenant_id: Tenant ID for tenant scoping.
    :param string tenant_name: Tenant name for tenant scoping.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True

    :raises TypeError: if a user_id or username is not provided.
    """

    # FIXME(stephenfin): The use of _unset is a hack to work around
    # misconfiguration issues with random services (bug #1361444). It needs to
    # go away asap. See change Id61cfd1423afa8f9dd964fda278f4fab40887512 for
    # more info.
    def __init__(
        self,
        auth_url: str,
        username: ty.Union[str, None, Unset] = _unset,
        password: ty.Optional[str] = None,
        user_id: ty.Union[str, None, Unset] = _unset,
        *,
        trust_id: ty.Optional[str] = None,
        tenant_id: ty.Optional[str] = None,
        tenant_name: ty.Optional[str] = None,
        reauthenticate: bool = True,
    ):
        super().__init__(
            auth_url,
            trust_id=trust_id,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            reauthenticate=reauthenticate,
        )

        if username is _unset and user_id is _unset:
            msg = 'You need to specify either a username or user_id'
            raise TypeError(msg)

        if username is _unset:
            self.username = None
        else:
            self.username = username

        if user_id is _unset:
            self.user_id = None
        else:
            self.user_id = user_id

        self.password = password

    def get_auth_data(
        self,
        headers: ty.Optional[collections.abc.MutableMapping[str, str]] = None,
    ) -> dict[str, object]:
        auth = {'password': self.password}

        if self.username:
            auth['username'] = self.username
        elif self.user_id:
            auth['userId'] = self.user_id

        return {'passwordCredentials': auth}

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        return {
            'username': self.username,
            'user_id': self.user_id,
            'password': self.password,
            'auth_url': self.auth_url,
            'tenant_id': self.tenant_id,
            'tenant_name': self.tenant_name,
            'trust_id': self.trust_id,
        }


class Token(Auth):
    """A plugin for authenticating with an existing token.

    :param string auth_url: Identity service endpoint for authorization.
    :param string token: Existing token for authentication.
    :param string tenant_id: Tenant ID for tenant scoping.
    :param string tenant_name: Tenant name for tenant scoping.
    :param string trust_id: Trust ID for trust scoping.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True
    """

    def __init__(
        self,
        auth_url: str,
        token: str,
        *,
        trust_id: ty.Optional[str] = None,
        tenant_id: ty.Optional[str] = None,
        tenant_name: ty.Optional[str] = None,
        reauthenticate: bool = True,
    ):
        super().__init__(
            auth_url,
            trust_id=trust_id,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            reauthenticate=reauthenticate,
        )
        self.token = token

    def get_auth_data(
        self,
        headers: ty.Optional[collections.abc.MutableMapping[str, str]] = None,
    ) -> dict[str, object]:
        if headers is not None:
            headers['X-Auth-Token'] = self.token
        return {'token': {'id': self.token}}

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        return {
            'token': self.token,
            'auth_url': self.auth_url,
            'tenant_id': self.tenant_id,
            'tenant_name': self.tenant_name,
            'trust_id': self.trust_id,
        }
