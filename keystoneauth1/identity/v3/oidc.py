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
import base64
import copy
import hashlib
import logging
import os
import time
import typing as ty
from urllib import parse as urlparse

import requests

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import federation
from keystoneauth1 import session as ks_session

_logger = utils.get_logger(__name__)

__all__ = (
    'OidcAuthorizationCode',
    'OidcClientCredentials',
    'OidcPassword',
    'OidcAccessToken',
)

SENSITIVE_KEYS = ("password", "code", "token", "secret")


_OidcBaseT = ty.TypeVar('_OidcBaseT', bound='_OidcBase')


class _OidcBase(federation.FederationBaseAuth, metaclass=abc.ABCMeta):
    """Base class for different OpenID Connect based flows.

    The OpenID Connect specification can be found at::
    ``http://openid.net/specs/openid-connect-core-1_0.html``
    """

    grant_type: ty.ClassVar[str]

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: ty.Optional[str],
        access_token_type: str,
        scope: str,
        access_token_endpoint: ty.Optional[str],
        discovery_endpoint: ty.Optional[str],
        *,
        trust_id: ty.Optional[str],
        system_scope: ty.Optional[str],
        domain_id: ty.Optional[str],
        domain_name: ty.Optional[str],
        project_id: ty.Optional[str],
        project_name: ty.Optional[str],
        project_domain_id: ty.Optional[str],
        project_domain_name: ty.Optional[str],
        reauthenticate: bool,
        include_catalog: bool,
    ):
        """The OpenID Connect plugin expects the following.

        :param auth_url: URL of the Identity Service
        :type auth_url: string

        :param identity_provider: Name of the Identity Provider the client
                                  will authenticate against
        :type identity_provider: string

        :param protocol: Protocol name as configured in keystone
        :type protocol: string

        :param client_id: OAuth 2.0 Client ID
        :type client_id: string

        :param client_secret: OAuth 2.0 Client Secret
        :type client_secret: string

        :param access_token_type: OAuth 2.0 Authorization Server Introspection
                                  token type, it is used to decide which type
                                  of token will be used when processing token
                                  introspection. Valid values are:
                                  "access_token" or "id_token"
        :type access_token_type: string

        :param access_token_endpoint: OpenID Connect Provider Token Endpoint,
                                      for example:
                                      https://localhost:8020/oidc/OP/token
                                      Note that if a discovery document is
                                      provided this value will override
                                      the discovered one.
        :type access_token_endpoint: string

        :param discovery_endpoint: OpenID Connect Discovery Document URL,
            for example:
            https://localhost:8020/oidc/.well-known/openid-configuration
        :type access_token_endpoint: string

        :param scope: OpenID Connect scope that is requested from OP,
                      for example: "openid profile email", defaults to
                      "openid profile". Note that OpenID Connect specification
                      states that "openid" must be always specified.
        :type scope: string
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
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

        self.client_id = client_id
        self.client_secret = client_secret

        self.discovery_endpoint = discovery_endpoint
        self._discovery_document: dict[str, object] = {}
        self.access_token_endpoint = access_token_endpoint

        self.access_token_type = access_token_type
        self.scope = scope

    def _get_discovery_document(
        self, session: ks_session.Session
    ) -> dict[str, object]:
        """Get the contents of the OpenID Connect Discovery Document.

        This method grabs the contents of the OpenID Connect Discovery Document
        if a discovery_endpoint was passed to the constructor and returns it as
        a dict, otherwise returns an empty dict. Note that it will fetch the
        discovery document only once, so subsequent calls to this method will
        return the cached result, if any.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a python dictionary containing the discovery document if any,
                  otherwise it will return an empty dict.
        :rtype: dict
        """
        if (
            self.discovery_endpoint is not None
            and not self._discovery_document
        ):
            try:
                resp = session.get(
                    self.discovery_endpoint, authenticated=False
                )
            except exceptions.HttpError:
                _logger.error(
                    f"Cannot fetch discovery document {self.discovery_endpoint}"
                )
                raise

            try:
                self._discovery_document = resp.json()
            except Exception:
                pass

            if not self._discovery_document:
                raise exceptions.InvalidOidcDiscoveryDocument()

        return self._discovery_document

    def _get_access_token_endpoint(self, session: ks_session.Session) -> str:
        """Get the "token_endpoint" for the OpenID Connect flow.

        This method will return the correct access token endpoint to be used.
        If the user has explicitly passed an access_token_endpoint to the
        constructor that will be returned. If there is no explicit endpoint and
        a discovery url is provided, it will try to get it from the discovery
        document. If nothing is found, an exception will be raised.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :return: the endpoint to use
        :rtype: string
        """
        if self.access_token_endpoint is not None:
            return self.access_token_endpoint

        discovery = self._get_discovery_document(session)
        endpoint = discovery.get("token_endpoint")
        if endpoint is None:
            raise exceptions.OidcAccessTokenEndpointNotFound()
        return ty.cast(str, endpoint)

    def _sanitize(
        self, data: dict[str, ty.Optional[str]]
    ) -> dict[str, ty.Optional[str]]:
        sanitized = copy.deepcopy(data)
        for key in sanitized:
            if any(s in key for s in SENSITIVE_KEYS):
                sanitized[key] = "***"
        return sanitized

    def _get_access_token(
        self, session: ks_session.Session, payload: dict[str, ty.Optional[str]]
    ) -> str:
        """Exchange a variety of user supplied values for an access token.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :param payload: a dict containing various OpenID Connect values, for
            example::

                {
                    'grant_type': 'password',
                    'username': self.username,
                    'password': self.password,
                    'scope': self.scope,
                }
        :type payload: dict
        """
        if self.client_secret:
            client_auth = (self.client_id, self.client_secret)
        else:
            client_auth = None
            payload.setdefault('client_id', self.client_id)
        access_token_endpoint = self._get_access_token_endpoint(session)

        if _logger.isEnabledFor(logging.DEBUG):
            sanitized_payload = self._sanitize(payload)
            _logger.debug(
                "Making OpenID-Connect authentication request to %s with "
                "data %s",
                access_token_endpoint,
                sanitized_payload,
            )

        op_response = session.post(
            access_token_endpoint,
            requests_auth=client_auth,
            data=payload,
            log=False,
            authenticated=False,
        )
        response = op_response.json()
        if _logger.isEnabledFor(logging.DEBUG):
            sanitized_response = self._sanitize(response)
            _logger.debug(
                "OpenID-Connect authentication response from %s is %s",
                access_token_endpoint,
                sanitized_response,
            )
        access_token = response[self.access_token_type]
        assert isinstance(access_token, str)  # nosec: B101
        return access_token

    def _get_keystone_token(
        self, session: ks_session.Session, access_token: str
    ) -> requests.Response:
        r"""Exchange an access token for a keystone token.

        By Sending the access token in an `Authorization: Bearer` header, to
        an OpenID Connect protected endpoint (Federated Token URL). The
        OpenID Connect server will use the access token to look up information
        about the authenticated user (this technique is called instrospection).
        The output of the instrospection will be an OpenID Connect Claim, that
        will be used against the mapping engine. Should the mapping engine
        succeed, a Keystone token will be presented to the user.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :param access_token: The OpenID Connect access token.
        :type access_token: str
        """
        # use access token against protected URL
        headers = {'Authorization': 'Bearer ' + access_token}
        auth_response = session.post(
            self.federated_token_url, headers=headers, authenticated=False
        )
        return auth_response

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Authenticate with OpenID Connect and get back claims.

        This is a multi-step process:

        1.- An access token must be retrieved from the server. In order to do
            so, we need to exchange an authorization grant or refresh token
            with the token endpoint in order to obtain an access token. The
            authorization grant varies from plugin to plugin.

        2.- We then exchange the access token upon accessing the protected
            Keystone endpoint (federated auth URL). This will trigger the
            OpenID Connect Provider to perform a user introspection and
            retrieve information (specified in the scope) about the user in the
            form of an OpenID Connect Claim. These claims will be sent to
            Keystone in the form of environment variables.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a token data representation
        :rtype: :py:class:`keystoneauth1.access.AccessInfoV3`
        """
        # First of all, check if the grant type is supported
        discovery = self._get_discovery_document(session)
        grant_types = ty.cast(
            ty.Optional[list[str]], discovery.get("grant_types_supported")
        )
        if (
            grant_types
            and self.grant_type is not None
            and self.grant_type not in grant_types
        ):
            raise exceptions.OidcPluginNotSupported()

        # Get the payload
        payload = self.get_payload(session)
        payload.setdefault('grant_type', self.grant_type)

        # get an access token
        access_token = self._get_access_token(session, payload)

        response = self._get_keystone_token(session, access_token)

        # grab the unscoped token
        access_info = access.create(resp=response)
        assert isinstance(access_info, access.AccessInfoV3)  # nosec B101
        return access_info

    @abc.abstractmethod
    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, ty.Optional[str]]:
        """Get the plugin specific payload for obtainin an access token.

        OpenID Connect supports different grant types. This method should
        prepare the payload that needs to be exchanged with the server in
        order to get an access token for the particular grant type that the
        plugin is implementing.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a python dictionary containing the payload to be exchanged
        :rtype: dict
        """
        raise NotImplementedError()


class OidcPassword(_OidcBase):
    """Implementation for OpenID Connect Resource Owner Password Credential."""

    grant_type = "password"

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str,
        access_token_type: str = 'access_token',  # nosec B107
        scope: str = 'openid profile',
        access_token_endpoint: ty.Optional[str] = None,
        discovery_endpoint: ty.Optional[str] = None,
        username: ty.Optional[str] = None,
        password: ty.Optional[str] = None,
        idp_otp_key: ty.Optional[str] = None,
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
        """The OpenID Password plugin expects the following.

        :param username: Username used to authenticate
        :type username: string

        :param password: Password used to authenticate
        :type password: string
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
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
        self.username = username
        self.password = password
        self.idp_otp_key = idp_otp_key

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, ty.Optional[str]]:
        """Get an authorization grant for the "password" grant type.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a python dictionary containing the payload to be exchanged
        :rtype: dict
        """
        payload = {
            'username': self.username,
            'password': self.password,
            'scope': self.scope,
            'client_id': self.client_id,
        }

        self.manage_otp_from_session_or_request_to_the_user(payload, session)

        return payload

    def manage_otp_from_session_or_request_to_the_user(
        self, payload: dict[str, ty.Optional[str]], session: ks_session.Session
    ) -> None:
        """Get the OTP code from the session or else request to the user.

        When the OS_IDP_OTP_KEY environment variable is set, this method will
        verify if there is an OTP value in the current session, if it exists,
        we use it (the OTP from session) to send to the Identity Provider when
        retrieving the access token. If there is no OTP in the current session,
        we ask the user to enter it (the OTP), and we add it to the session to
        execute the authentication flow.

        The OTP is being stored in the session because in some flows, the CLI
        is doing the authentication process two times, so saving the OTP
        in the session, allow us to use the same OTP in a short time interval,
        avoiding to request it to the user twice in a row.

        :param payload:
        :param session:
        :return:
        """
        if not self.idp_otp_key:
            return

        otp_from_session = getattr(session, 'otp', None)
        if otp_from_session:
            payload[self.idp_otp_key] = otp_from_session
        else:
            payload[self.idp_otp_key] = input(
                "Please, enter the generated OTP code: "
            )
            setattr(session, 'otp', payload[self.idp_otp_key])


class OidcClientCredentials(_OidcBase):
    """Implementation for OpenID Connect Client Credentials."""

    grant_type = 'client_credentials'

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str,
        access_token_type: str = 'access_token',  # nosec B107
        scope: str = 'openid profile',
        access_token_endpoint: ty.Optional[str] = None,
        discovery_endpoint: ty.Optional[str] = None,
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
        """The OpenID Client Credentials expects the following.

        :param client_id: Client ID used to authenticate
        :type username: string

        :param client_secret: Client Secret used to authenticate
        :type password: string
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
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

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, ty.Optional[str]]:
        """Get an authorization grant for the client credentials grant type.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a python dictionary containing the payload to be exchanged
        :rtype: dict
        """
        payload: dict[str, ty.Optional[str]] = {'scope': self.scope}
        return payload


class OidcAuthorizationCode(_OidcBase):
    """Implementation for OpenID Connect Authorization Code."""

    grant_type = 'authorization_code'

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str,
        access_token_type: str = 'access_token',  # nosec B107
        scope: str = 'openid profile',
        access_token_endpoint: ty.Optional[str] = None,
        discovery_endpoint: ty.Optional[str] = None,
        code: ty.Optional[str] = None,
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
        redirect_uri: ty.Optional[str] = None,
    ):
        """The OpenID Authorization Code plugin expects the following.

        :param redirect_uri: OpenID Connect Client Redirect URL
        :type redirect_uri: string

        :param code: OAuth 2.0 Authorization Code
        :type code: string

        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
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
        self.redirect_uri = redirect_uri
        self.code = code

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, ty.Optional[str]]:
        """Get an authorization grant for the "authorization_code" grant type.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a python dictionary containing the payload to be exchanged
        :rtype: dict
        """
        payload = {'redirect_uri': self.redirect_uri, 'code': self.code}

        return payload


class OidcAccessToken(_OidcBase):
    """Implementation for OpenID Connect access token reuse."""

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        # client_id and client_id intentionally omitted since they don't make
        # sense with an access token
        access_token_type: str = 'access_token',  # nosec B107
        scope: str = 'openid profile',
        access_token_endpoint: ty.Optional[str] = None,
        discovery_endpoint: ty.Optional[str] = None,
        access_token: ty.Optional[str] = None,
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
        """The OpenID Connect plugin based on the Access Token.

        It expects the following:

        :param auth_url: URL of the Identity Service
        :type auth_url: string

        :param identity_provider: Name of the Identity Provider the client
                                  will authenticate against
        :type identity_provider: string

        :param protocol: Protocol name as configured in keystone
        :type protocol: string

        :param access_token: OpenID Connect Access token
        :type access_token: string
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            # intentionally set client_id, client_secret to empty since we
            # don't need then
            client_id='',  # nosec B106
            client_secret='',  # nosec B106
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
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
        assert access_token is not None  # nosec B101
        self.access_token = access_token

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, ty.Optional[str]]:
        """OidcAccessToken does not require a payload."""  # noqa: D403
        return {}

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Authenticate with OpenID Connect and get back claims.

        We exchange the access token upon accessing the protected Keystone
        endpoint (federated auth URL). This will trigger the OpenID Connect
        Provider to perform a user introspection and retrieve information
        (specified in the scope) about the user in the form of an OpenID
        Connect Claim. These claims will be sent to Keystone in the form of
        environment variables.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a token data representation
        :rtype: :py:class:`keystoneauth1.access.AccessInfoV3`
        """
        response = self._get_keystone_token(session, self.access_token)
        access_info = access.create(resp=response)
        assert isinstance(access_info, access.AccessInfoV3)  # nosec B101
        return access_info


class OidcDeviceAuthorization(_OidcBase):
    """Implementation for OAuth 2.0 Device Authorization Grant."""

    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
    HEADER_X_FORM = {"Content-Type": "application/x-www-form-urlencoded"}

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: ty.Optional[str],
        # access_token_type intentionally skipped
        scope: str = 'openid profile',
        access_token_endpoint: ty.Optional[str] = None,
        discovery_endpoint: ty.Optional[str] = None,
        device_authorization_endpoint: ty.Optional[str] = None,
        code_challenge: ty.Optional[str] = None,
        code_challenge_method: ty.Optional[str] = None,
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
        """The OAuth 2.0 Device Authorization plugin expects the following.

        :param device_authorization_endpoint: OAuth 2.0 Device Authorization
                                  Endpoint, for example:
                                  https://localhost:8020/oidc/authorize/device
                                  Note that if a discovery document is
                                  provided this value will override
                                  the discovered one.
        :type device_authorization_endpoint: string

        :param code_challenge_method: PKCE Challenge Method (RFC 7636).
        :type code_challenge_method: string
        """
        # RFC 8628 only allows to retrieve an access_token
        self.access_token_type = 'access_token'  # nosec B105
        self.device_authorization_endpoint = device_authorization_endpoint
        self.code_challenge_method = code_challenge_method

        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=self.access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
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

    def _get_device_authorization_endpoint(
        self, session: ks_session.Session
    ) -> ty.Optional[str]:
        """Get the endpoint for the OAuth 2.0 Device Authorization flow.

        This method will return the correct device authorization endpoint to
        be used.
        If the user has explicitly passed an device_authorization_endpoint to
        the constructor that will be returned. If there is no explicit endpoint
        and a discovery url is provided, it will try to get it from the
        discovery document. If nothing is found, an exception will be raised.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :return: the endpoint to use
        :rtype: string or None if no endpoint is found
        """
        if self.device_authorization_endpoint is not None:
            return self.device_authorization_endpoint

        discovery = self._get_discovery_document(session)
        endpoint = discovery.get("device_authorization_endpoint")
        if endpoint is None:
            raise exceptions.oidc.OidcDeviceAuthorizationEndpointNotFound()
        return ty.cast(str, endpoint)

    def _generate_pkce_verifier(self) -> str:
        """Generate PKCE verifier string as defined in RFC 7636."""
        raw_bytes = 42  # 32 is the minimum from the RFC, let's use a bit more
        _rand = os.urandom(raw_bytes)
        _rand_b64 = base64.urlsafe_b64encode(_rand).decode('ascii')
        code_verifier = _rand_b64.rstrip('=')  # strip padding as RFC says
        return code_verifier

    def _generate_pkce_challenge(self) -> ty.Optional[str]:
        """Generate PKCE challenge string as defined in RFC 7636."""
        if self.code_challenge_method not in ('plain', 'S256'):
            raise exceptions.OidcInvalidCodeChallengeMethod()
        self.code_verifier = self._generate_pkce_verifier()

        if self.code_challenge_method == 'plain':
            return self.code_verifier
        elif self.code_challenge_method == 'S256':
            _tmp = self.code_verifier.encode('ascii')
            _hash = hashlib.sha256(_tmp).digest()
            return base64.urlsafe_b64encode(_hash).decode('ascii').rstrip('=')

        return None

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, ty.Optional[str]]:
        """Get an authorization grant for the "device_code" grant type.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a python dictionary containing the payload to be exchanged
        :rtype: dict
        """
        payload: dict[str, ty.Optional[str]]
        device_authz_endpoint = self._get_device_authorization_endpoint(
            session
        )

        # TODO(stephenfin): This should be an error
        assert device_authz_endpoint is not None  # nosec B101

        if self.client_secret:
            client_auth = (self.client_id, self.client_secret)
            payload = {}
        else:
            client_auth = None
            payload = {'client_id': self.client_id}

        if self.code_challenge_method:
            self.code_challenge = self._generate_pkce_challenge()
            payload.setdefault(
                'code_challenge_method', self.code_challenge_method
            )
            payload.setdefault('code_challenge', self.code_challenge)
        encoded_payload = urlparse.urlencode(payload)

        if _logger.isEnabledFor(logging.DEBUG):
            sanitized_payload = self._sanitize(payload)
            _logger.debug(
                "Making OpenID-Connect authentication request to %s with "
                "data %s",
                device_authz_endpoint,
                sanitized_payload,
            )
        op_response = session.post(
            device_authz_endpoint,
            requests_auth=client_auth,
            headers=self.HEADER_X_FORM,
            data=encoded_payload,
            log=False,
            authenticated=False,
        )
        if _logger.isEnabledFor(logging.DEBUG):
            sanitized_response = self._sanitize(op_response.json())
            _logger.debug(
                "OpenID-Connect authentication response from %s is %s",
                device_authz_endpoint,
                sanitized_response,
            )

        self.expires_in = int(op_response.json()["expires_in"])
        self.timeout = time.time() + self.expires_in
        self.device_code = op_response.json()["device_code"]
        self.interval = int(op_response.json()["interval"])
        self.user_code = op_response.json()["user_code"]
        self.verification_uri = op_response.json()["verification_uri"]
        self.verification_uri_complete = op_response.json()[
            "verification_uri_complete"
        ]

        payload = {'device_code': self.device_code}
        if self.code_challenge_method:
            payload.setdefault('code_verifier', self.code_verifier)
        return payload

    def _get_access_token(
        self, session: ks_session.Session, payload: dict[str, ty.Optional[str]]
    ) -> str:
        """Poll token endpoint for an access token.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :param payload: a dict containing various OpenID Connect values,
            for example::

                {
                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                    'device_code': self.device_code,
                }
        :type payload: dict
        """
        _logger.warning(
            f"To authenticate please go to: {self.verification_uri_complete}"
        )

        if self.client_secret:
            client_auth = (self.client_id, self.client_secret)
        else:
            client_auth = None
            payload.setdefault('client_id', self.client_id)

        access_token_endpoint = self._get_access_token_endpoint(session)
        encoded_payload = urlparse.urlencode(payload)

        while time.time() < self.timeout:
            try:
                if _logger.isEnabledFor(logging.DEBUG):
                    sanitized_payload = self._sanitize(payload)
                    _logger.debug(
                        "Making OpenID-Connect authentication request to %s "
                        "with data %s",
                        access_token_endpoint,
                        sanitized_payload,
                    )
                op_response = session.post(
                    access_token_endpoint,
                    requests_auth=client_auth,
                    data=encoded_payload,
                    headers=self.HEADER_X_FORM,
                    log=False,
                    authenticated=False,
                )
                if _logger.isEnabledFor(logging.DEBUG):
                    sanitized_response = self._sanitize(op_response.json())
                    _logger.debug(
                        "OpenID-Connect authentication response from %s is %s",
                        access_token_endpoint,
                        sanitized_response,
                    )
            except exceptions.http.BadRequest as exc:
                error = exc.response and exc.response.json().get("error")
                if error != "authorization_pending":
                    raise
                time.sleep(self.interval)
                continue
            break
        else:
            if error == "authorization_pending":
                raise exceptions.oidc.OidcDeviceAuthorizationTimeOut()

        access_token = op_response.json()[self.access_token_type]
        assert isinstance(access_token, str)  # nosec B101
        return access_token
