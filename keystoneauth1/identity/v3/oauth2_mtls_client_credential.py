# Copyright 2022 OpenStack Foundation
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

import abc
import typing as ty

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import base
from keystoneauth1 import session as ks_session


class OAuth2mTlsClientCredential(base.BaseAuth, metaclass=abc.ABCMeta):
    """A plugin for authenticating via an OAuth2.0 mTLS client credential.

    :param string auth_url: keystone authorization endpoint.
    :param string oauth2_endpoint: OAuth2.0 endpoint.
    :param string oauth2_client_id: OAuth2.0 client credential id.
    """

    def __init__(
        self,
        auth_url: str,
        oauth2_endpoint: str,
        oauth2_client_id: str,
        *,
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
        self.oauth2_endpoint = oauth2_endpoint
        self.oauth2_client_id = oauth2_client_id
        self.oauth2_access_token = None

    def get_auth_ref(self, session: ks_session.Session) -> access.AccessInfoV3:
        """Obtain a token from an OpenStack Identity Service.

        This method is overridden by the various token version plugins.

        This function should not be called independently and is expected to be
        invoked via the do_authenticate function.

        This function will be invoked if the AcessInfo object cached by the
        plugin is not valid. Thus plugins should always fetch a new AccessInfo
        when invoked. If you are looking to just retrieve the current auth
        data then you should use get_access.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.response.InvalidResponse:
            The response returned wasn't appropriate.
        :raises keystoneauth1.exceptions.http.HttpError:
            An error from an invalid HTTP response.
        :raises keystoneauth1.exceptions.ClientException:
            An error from getting OAuth2.0 access token.

        :returns: Token access information.
        :rtype: :class:`keystoneauth1.access.AccessInfo`
        """
        # Get OAuth2.0 access token and add the field 'Authorization' when
        # using the HTTPS protocol.
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.oauth2_client_id,
        }
        resp = session.post(
            url=self.oauth2_endpoint,
            authenticated=False,
            raise_exc=False,
            data=data,
        )
        if resp.status_code == 200:
            oauth2 = resp.json()
            self.oauth2_access_token = oauth2.get('access_token')
        else:
            error = resp.json()
            msg = error.get('error_description')
            raise exceptions.ClientException(msg)

        headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.oauth2_access_token,
            'X-Subject-Token': self.oauth2_access_token,
        }

        token_url = '{}/auth/tokens'.format(self.auth_url.rstrip('/'))
        if not self.auth_url.rstrip('/').endswith('v3'):
            token_url = '{}/v3/auth/tokens'.format(self.auth_url.rstrip('/'))
        resp = session.get(
            url=token_url, authenticated=False, headers=headers, log=False
        )
        try:
            resp_data = resp.json()
        except ValueError:
            raise exceptions.InvalidResponse(response=resp)
        if 'token' not in resp_data:
            raise exceptions.InvalidResponse(response=resp)

        return access.AccessInfoV3(
            auth_token=self.oauth2_access_token, body=resp_data
        )

    def get_headers(
        self, session: 'ks_session.Session'
    ) -> ty.Optional[dict[str, str]]:
        """Fetch authentication headers for message.

        :param session: The session object that the auth_plugin belongs to.
        :type session: keystoneauth1.session.Session

        :returns: Headers that are set to authenticate a message or None for
                  failure. Note that when checking this value that the empty
                  dict is a valid, non-failure response.
        :rtype: dict
        """
        # get headers for X-Auth-Token
        headers = super().get_headers(session)

        # add OAuth2.0 access token to the headers
        if headers:
            headers['Authorization'] = f'Bearer {self.oauth2_access_token}'
        else:
            headers = {'Authorization': f'Bearer {self.oauth2_access_token}'}
        return headers
