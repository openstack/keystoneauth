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

import requests.auth

from keystoneauth1.exceptions import ClientException
from keystoneauth1.identity.v3 import base

__all__ = ('OAuth2ClientCredentialMethod', 'OAuth2ClientCredential')


class OAuth2ClientCredentialMethod(base.AuthMethod):
    """An auth method to fetch a token via an OAuth2.0 client credential.

    :param string oauth2_endpoint: OAuth2.0 endpoint.
    :param string oauth2_client_id: OAuth2.0 client credential id.
    :param string oauth2_client_secret: OAuth2.0 client credential secret.
    """

    _method_parameters = [
        'oauth2_endpoint',
        'oauth2_client_id',
        'oauth2_client_secret',
    ]

    def get_auth_data(self, session, auth, headers, **kwargs):
        """Return the authentication section of an auth plugin.

        :param session: The communication session.
        :type session: keystoneauth1.session.Session
        :param base.Auth auth: The auth plugin calling the method.
        :param dict headers: The headers that will be sent with the auth
                             request if a plugin needs to add to them.
        :return: The identifier of this plugin and a dict of authentication
                 data for the auth type.
        :rtype: tuple(string, dict)
        """
        auth_data = {
            'id': self.oauth2_client_id,
            'secret': self.oauth2_client_secret,
        }
        return 'application_credential', auth_data

    def get_cache_id_elements(self):
        """Get the elements for this auth method that make it unique.

        These elements will be used as part of the
        :py:meth:`keystoneauth1.plugin.BaseIdentityPlugin.get_cache_id` to
        allow caching of the auth plugin.

        Plugins should override this if they want to allow caching of their
        state.

        To avoid collision or overrides the keys of the returned dictionary
        should be prefixed with the plugin identifier. For example the password
        plugin returns its username value as 'password_username'.
        """
        return {
            f'oauth2_client_credential_{p}': getattr(self, p)
            for p in self._method_parameters
        }


class OAuth2ClientCredential(base.AuthConstructor):
    """A plugin for authenticating via an OAuth2.0 client credential.

    :param string auth_url: Identity service endpoint for authentication.
    :param string oauth2_endpoint: OAuth2.0 endpoint.
    :param string oauth2_client_id: OAuth2.0 client credential id.
    :param string oauth2_client_secret: OAuth2.0 client credential secret.
    """

    _auth_method_class = OAuth2ClientCredentialMethod

    def __init__(self, auth_url, *args, **kwargs):
        super().__init__(auth_url, *args, **kwargs)
        self._oauth2_endpoint = kwargs['oauth2_endpoint']
        self._oauth2_client_id = kwargs['oauth2_client_id']
        self._oauth2_client_secret = kwargs['oauth2_client_secret']

    def get_headers(self, session, **kwargs):
        """Fetch authentication headers for message.

        :param session: The session object that the auth_plugin belongs to.
        :type session: keystoneauth1.session.Session

        :returns: Headers that are set to authenticate a message or None for
                  failure. Note that when checking this value that the empty
                  dict is a valid, non-failure response.
        :rtype: dict
        """
        # get headers for X-Auth-Token
        headers = super().get_headers(session, **kwargs)

        # Get OAuth2.0 access token and add the field 'Authorization'
        data = {"grant_type": "client_credentials"}
        auth = requests.auth.HTTPBasicAuth(
            self._oauth2_client_id, self._oauth2_client_secret
        )
        resp = session.request(
            self._oauth2_endpoint,
            "POST",
            authenticated=False,
            raise_exc=False,
            data=data,
            requests_auth=auth,
        )
        if resp.status_code == 200:
            oauth2 = resp.json()
            oauth2_token = oauth2["access_token"]
            if headers:
                headers['Authorization'] = f'Bearer {oauth2_token}'
            else:
                headers = {'Authorization': f'Bearer {oauth2_token}'}
        else:
            error = resp.json()
            msg = error.get("error_description")
            raise ClientException(msg)

        return headers
