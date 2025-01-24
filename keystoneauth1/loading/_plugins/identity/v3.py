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

from keystoneauth1 import exceptions
from keystoneauth1 import identity
from keystoneauth1.identity.v3 import oidc
from keystoneauth1 import loading
from keystoneauth1.loading import opts


def _add_common_identity_options(options: list[opts.Opt]) -> None:
    options.extend(
        [
            loading.Opt('user-id', help="User's user ID"),
            loading.Opt(
                'username',
                help="User's username",
                deprecated=[loading.Opt('user-name')],
            ),
            loading.Opt('user-domain-id', help="User's domain ID"),
            loading.Opt('user-domain-name', help="User's domain name"),
        ]
    )


def _assert_identity_options(options: dict[str, ty.Any]) -> None:
    if options.get('username') and not (
        options.get('user_domain_name') or options.get('user_domain_id')
    ):
        m = (
            "You have provided a username. In the V3 identity API a "
            "username is only unique within a domain so you must "
            "also provide either a user_domain_id or user_domain_name."
        )
        raise exceptions.OptionError(m)


class Password(loading.BaseV3Loader[identity.V3Password]):
    """Authenticate with a username and password.

    Authenticate to the identity service using the provided username and
    password. This is the standard and most common form of authentication.
    """

    @property
    def plugin_class(self) -> ty.Type[identity.V3Password]:
        return identity.V3Password

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()
        _add_common_identity_options(options)

        options.extend(
            [
                loading.Opt(
                    'password',
                    secret=True,
                    prompt='Password: ',
                    help="User's password",
                )
            ]
        )

        return options

    def load_from_options(self, **kwargs: ty.Any) -> identity.V3Password:
        _assert_identity_options(kwargs)

        return super().load_from_options(**kwargs)


class Token(loading.BaseV3Loader[identity.V3Token]):
    """Given an existing token rescope it to another target.

    Use the Identity service's rescope mechanism to get a new token based upon
    an existing token. Because an auth plugin requires a service catalog and
    scope information it is often easier to fetch a new token based on an
    existing one than validate and reuse the one you already have.
    """

    @property
    def plugin_class(self) -> ty.Type[identity.V3Token]:
        return identity.V3Token

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'token', secret=True, help='Token to authenticate with'
                )
            ]
        )

        return options


class _OpenIDConnectBase(loading.BaseFederationLoader[oidc._OidcBaseT]):
    def load_from_options(self, **kwargs: ty.Any) -> oidc._OidcBaseT:
        if not (
            kwargs.get('access_token_endpoint')
            or kwargs.get('discovery_endpoint')
        ):
            m = (
                "You have to specify either an 'access-token-endpoint' or "
                "a 'discovery-endpoint'."
            )
            raise exceptions.OptionError(m)

        return super().load_from_options(**kwargs)

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt('client-id', help='OAuth 2.0 Client ID'),
                loading.Opt(
                    'client-secret',
                    secret=True,
                    help='OAuth 2.0 Client Secret',
                ),
                loading.Opt(
                    'openid-scope',
                    default="openid profile",
                    dest="scope",
                    help='OpenID Connect scope that is requested from '
                    'authorization server. Note that the OpenID '
                    'Connect specification states that "openid" '
                    'must be always specified.',
                ),
                loading.Opt(
                    'access-token-endpoint',
                    help='OpenID Connect Provider Token Endpoint. Note '
                    'that if a discovery document is being passed this '
                    'option will override the endpoint provided by the '
                    'server in the discovery document.',
                ),
                loading.Opt(
                    'discovery-endpoint',
                    help='OpenID Connect Discovery Document URL. '
                    'The discovery document will be used to obtain the '
                    'values of the access token endpoint and the '
                    'authentication endpoint. This URL should look like '
                    'https://idp.example.org/.well-known/'
                    'openid-configuration',
                ),
                loading.Opt(
                    'access-token-type',
                    help='OAuth 2.0 Authorization Server Introspection '
                    'token type, it is used to decide which type '
                    'of token will be used when processing token '
                    'introspection. Valid values are: '
                    '"access_token" or "id_token"',
                ),
            ]
        )

        return options


class OpenIDConnectClientCredentials(
    _OpenIDConnectBase[identity.V3OidcClientCredentials]
):
    """Authenticate with the OIDC Client Credentials flow."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3OidcClientCredentials]:
        return identity.V3OidcClientCredentials

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        return options


class OpenIDConnectPassword(_OpenIDConnectBase[identity.V3OidcPassword]):
    """Authenticate with the OIDC Resource Owner Password Credentials flow."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3OidcPassword]:
        return identity.V3OidcPassword

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt('username', help='Username', required=True),
                loading.Opt(
                    'password', secret=True, help='Password', required=True
                ),
                loading.Opt(
                    'idp_otp_key',
                    help='A key to be used in the Identity Provider access'
                    ' token endpoint to pass the OTP value. '
                    'E.g. totp',
                ),
            ]
        )

        return options


class OpenIDConnectAuthorizationCode(
    _OpenIDConnectBase[identity.V3OidcAuthorizationCode]
):
    """Authenticate with the OIDC Authorization Code flow."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3OidcAuthorizationCode]:
        return identity.V3OidcAuthorizationCode

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'redirect-uri', help='OpenID Connect Redirect URL'
                ),
                loading.Opt(
                    'code',
                    secret=True,
                    required=True,
                    deprecated=[loading.Opt('authorization-code')],
                    help='OAuth 2.0 Authorization Code',
                ),
            ]
        )

        return options


class OpenIDConnectAccessToken(
    loading.BaseFederationLoader[identity.V3OidcAccessToken]
):
    """Authenticate with the OIDC Access Token flow."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3OidcAccessToken]:
        return identity.V3OidcAccessToken

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'access-token',
                    secret=True,
                    required=True,
                    help='OAuth 2.0 Access Token',
                )
            ]
        )
        return options


class OpenIDConnectDeviceAuthorization(
    _OpenIDConnectBase[identity.V3OidcDeviceAuthorization]
):
    """Authenticate with the OAuth 2.0 Device Authorization flow."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3OidcDeviceAuthorization]:
        return identity.V3OidcDeviceAuthorization

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        # RFC 8628 doesn't support id_token
        options = [opt for opt in options if opt.name != 'access-token-type']

        options.extend(
            [
                loading.Opt(
                    'device-authorization-endpoint',
                    help='OAuth 2.0 Device Authorization Endpoint. Note '
                    'that if a discovery document is being passed this '
                    'option will override the endpoint provided by the '
                    'server in the discovery document.',
                ),
                loading.Opt(
                    'code-challenge-method',
                    help='PKCE Challenge Method (RFC 7636)',
                ),
            ]
        )

        return options


class TOTP(loading.BaseV3Loader[identity.V3TOTP]):
    """Authenticate with a Time-based One-Time Password.

    Authenticate to the identity service using a time-based one-time password.
    This is typically used in combination with another plugin as part of a
    multi-factor configuration.
    """

    @property
    def plugin_class(self) -> ty.Type[identity.V3TOTP]:
        return identity.V3TOTP

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()
        _add_common_identity_options(options)

        options.extend(
            [
                loading.Opt(
                    'passcode',
                    secret=True,
                    prompt='TOTP passcode: ',
                    help="User's TOTP passcode",
                )
            ]
        )

        return options

    def load_from_options(self, **kwargs: ty.Any) -> identity.V3TOTP:
        _assert_identity_options(kwargs)

        return super().load_from_options(**kwargs)


class TokenlessAuth(loading.BaseLoader[identity.V3TokenlessAuth]):
    """Authenticate without a token, using an X.509 certificate."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3TokenlessAuth]:
        return identity.V3TokenlessAuth

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'auth-url', required=True, help='Authentication URL'
                ),
                loading.Opt('domain-id', help='Domain ID to scope to'),
                loading.Opt('domain-name', help='Domain name to scope to'),
                loading.Opt('project-id', help='Project ID to scope to'),
                loading.Opt('project-name', help='Project name to scope to'),
                loading.Opt(
                    'project-domain-id', help='Domain ID containing project'
                ),
                loading.Opt(
                    'project-domain-name',
                    help='Domain name containing project',
                ),
            ]
        )

        return options

    def load_from_options(self, **kwargs: ty.Any) -> identity.V3TokenlessAuth:
        if (
            not kwargs.get('domain_id')
            and not kwargs.get('domain_name')
            and not kwargs.get('project_id')
            and not kwargs.get('project_name')
            or (
                kwargs.get('project_name')
                and not (
                    kwargs.get('project_domain_name')
                    or kwargs.get('project_domain_id')
                )
            )
        ):
            m = (
                'You need to provide either a domain_name, domain_id, '
                'project_id or project_name. '
                'If you have provided a project_name, in the V3 identity '
                'API a project_name is only unique within a domain so '
                'you must also provide either a project_domain_id or '
                'project_domain_name.'
            )
            raise exceptions.OptionError(m)

        return super().load_from_options(**kwargs)


class ApplicationCredential(
    loading.BaseV3Loader[identity.V3ApplicationCredential]
):
    """Authenticate with an application credential.

    Authenticate to the identity service using the provided application
    credential secret and ID or name. If a name is used, you must also provide
    a username and user domain to assist in lookup.
    """

    @property
    def plugin_class(self) -> ty.Type[identity.V3ApplicationCredential]:
        return identity.V3ApplicationCredential

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()
        _add_common_identity_options(options)

        options.extend(
            [
                loading.Opt(
                    'application_credential_secret',
                    secret=True,
                    required=True,
                    help="Application credential auth secret",
                ),
                loading.Opt(
                    'application_credential_id',
                    help='Application credential ID',
                ),
                loading.Opt(
                    'application_credential_name',
                    help='Application credential name',
                ),
            ]
        )

        return options

    def load_from_options(
        self, **kwargs: ty.Any
    ) -> identity.V3ApplicationCredential:
        _assert_identity_options(kwargs)
        if not kwargs.get('application_credential_id') and not kwargs.get(
            'application_credential_name'
        ):
            m = (
                'You must provide either an application credential ID or an '
                'application credential name and user.'
            )
            raise exceptions.OptionError(m)
        if not kwargs.get('application_credential_secret'):
            m = 'You must provide an auth secret.'
            raise exceptions.OptionError(m)

        return super().load_from_options(**kwargs)


class MultiFactor(loading.BaseV3Loader[identity.V3MultiFactor]):
    """Authenticate using multiple factors.

    Authenticate to the identity service using a combination of factors, such
    as username/password and a TOTP code.
    """

    def __init__(self) -> None:
        super().__init__()
        self._methods = None

    @property
    def plugin_class(self) -> ty.Type[identity.V3MultiFactor]:
        return identity.V3MultiFactor

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()

        options.extend(
            [
                loading.Opt(
                    'auth_methods',
                    required=True,
                    help="Methods to authenticate with.",
                )
            ]
        )

        if self._methods:
            options_dict = {o.name: o for o in options}
            for method in self._methods:
                method_opts = loading.get_plugin_options(method)
                for opt in method_opts:
                    options_dict[opt.name] = opt
            options = list(options_dict.values())
        return options

    def load_from_options(self, **kwargs: ty.Any) -> identity.V3MultiFactor:
        _assert_identity_options(kwargs)

        if 'auth_methods' not in kwargs:
            raise exceptions.OptionError("methods is a required option.")

        self._methods = kwargs['auth_methods']

        return super().load_from_options(**kwargs)


class OAuth2ClientCredential(
    loading.BaseV3Loader[identity.V3OAuth2ClientCredential]
):
    """Authenticate with an OAuth2.0 client credential."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3OAuth2ClientCredential]:
        return identity.V3OAuth2ClientCredential

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()
        options.extend(
            [
                loading.Opt(
                    'oauth2_endpoint',
                    required=True,
                    help='Endpoint for OAuth2.0',
                ),
                loading.Opt(
                    'oauth2_client_id',
                    required=True,
                    help='Client id for OAuth2.0',
                ),
                loading.Opt(
                    'oauth2_client_secret',
                    secret=True,
                    required=True,
                    help='Client secret for OAuth2.0',
                ),
            ]
        )

        return options

    def load_from_options(
        self, **kwargs: ty.Any
    ) -> identity.V3OAuth2ClientCredential:
        if not kwargs.get('oauth2_endpoint'):
            m = 'You must provide an OAuth2.0 endpoint.'
            raise exceptions.OptionError(m)
        if not kwargs.get('oauth2_client_id'):
            m = 'You must provide an OAuth2.0 client credential ID.'
            raise exceptions.OptionError(m)
        if not kwargs.get('oauth2_client_secret'):
            m = 'You must provide an OAuth2.0 client credential auth secret.'
            raise exceptions.OptionError(m)

        return super().load_from_options(**kwargs)


class OAuth2mTlsClientCredential(
    loading.BaseV3Loader[identity.V3OAuth2mTlsClientCredential]
):
    """Authenticate with an OAuth2.0 mTLS client credential."""

    @property
    def plugin_class(self) -> ty.Type[identity.V3OAuth2mTlsClientCredential]:
        return identity.V3OAuth2mTlsClientCredential

    def get_options(self) -> list[opts.Opt]:
        options = super().get_options()
        options.extend(
            [
                loading.Opt(
                    'oauth2-endpoint',
                    required=True,
                    help='Endpoint for OAuth2.0 Mutual-TLS Authorization',
                ),
                loading.Opt(
                    'oauth2-client-id',
                    required=True,
                    help='Client credential ID for OAuth2.0 Mutual-TLS '
                    'Authorization',
                ),
            ]
        )
        return options

    def load_from_options(
        self, **kwargs: ty.Any
    ) -> identity.V3OAuth2mTlsClientCredential:
        if not kwargs.get('oauth2_endpoint'):
            m = 'You must provide an OAuth2.0 Mutual-TLS endpoint.'
            raise exceptions.OptionError(m)
        if not kwargs.get('oauth2_client_id'):
            m = (
                'You must provide an client credential ID for '
                'OAuth2.0 Mutual-TLS Authorization.'
            )
            raise exceptions.OptionError(m)
        return super().load_from_options(**kwargs)
