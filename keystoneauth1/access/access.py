# Copyright 2012 Nebula, Inc.
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import typing as ty

import requests

from keystoneauth1 import _utils as utils
from keystoneauth1.access import service_catalog
from keystoneauth1.access import service_providers
from keystoneauth1.access import types

# gap, in seconds, to determine whether the given token is about to expire
STALE_TOKEN_DURATION = 30

__all__ = ('AccessInfo', 'AccessInfoV2', 'AccessInfoV3', 'create')


def create(
    resp: ty.Optional[requests.Response] = None,
    body: ty.Optional[dict[str, object]] = None,
    auth_token: ty.Optional[str] = None,
) -> 'AccessInfo':
    if resp and not body:
        body = resp.json()

    assert body is not None  # nosec B101

    if 'token' in body:
        if resp and not auth_token:
            auth_token = resp.headers.get('X-Subject-Token')

        return AccessInfoV3(body, auth_token)
    elif 'access' in body:
        return AccessInfoV2(body, auth_token)

    raise ValueError('Unrecognized auth response')


class AccessInfo:
    """Encapsulates a raw authentication token from keystone.

    Provides helper methods for extracting useful values from that token.
    """

    _service_catalog_class: ty.Type[service_catalog.ServiceCatalog]
    _data: ty.Any

    def __init__(
        self, body: dict[str, ty.Any], auth_token: ty.Optional[str] = None
    ):
        self._data = body
        self._auth_token = auth_token
        self._service_catalog: ty.Optional[service_catalog.ServiceCatalog] = (
            None
        )
        self._service_providers: ty.Optional[
            service_providers.ServiceProviders
        ] = None

    @property
    def service_catalog(self) -> service_catalog.ServiceCatalog:
        if not self._service_catalog:
            self._service_catalog = self._service_catalog_class.from_token(
                self._data
            )

        return self._service_catalog

    def will_expire_soon(
        self, stale_duration: int = STALE_TOKEN_DURATION
    ) -> bool:
        """Determine if expiration is about to occur.

        :returns: true if expiration is within the given duration
        :rtype: boolean
        """
        if self.expires is None:
            return False

        norm_expires = utils.normalize_time(self.expires)
        # (gyee) should we move auth_token.will_expire_soon() to timeutils
        # instead of duplicating code here?
        soon = utils.from_utcnow(seconds=stale_duration)
        return norm_expires < soon

    def has_service_catalog(self) -> bool:
        """Return true if the auth token has a service catalog.

        :returns: boolean
        """
        raise NotImplementedError()

    @property
    def auth_token(self) -> ty.Optional[str]:
        """Return the token_id associated with the auth request.

        To be used in headers for authenticating OpenStack API requests.

        :returns: str
        """
        return self._auth_token

    @property
    def expires(self) -> ty.Optional[datetime.datetime]:
        """Return the token expiration (as datetime object).

        :returns: datetime
        """
        raise NotImplementedError()

    @property
    def issued(self) -> ty.Optional[datetime.datetime]:
        """Return the token issue time (as datetime object).

        :returns: datetime
        """
        raise NotImplementedError()

    @property
    def username(self) -> ty.Optional[str]:
        """Return the username associated with the auth request.

        Follows the pattern defined in the V2 API of first looking for 'name',
        returning that if available, and falling back to 'username' if name
        is unavailable.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def user_id(self) -> ty.Optional[str]:
        """Return the user id associated with the auth request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def user_domain_id(self) -> ty.Optional[str]:
        """Return the user's domain id associated with the auth request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def user_domain_name(self) -> ty.Optional[str]:
        """Return the user's domain name associated with the auth request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def role_ids(self) -> ty.Optional[list[str]]:
        """Return a list of user's role ids associated with the auth request.

        :returns: a list of strings of role ids
        """
        raise NotImplementedError()

    @property
    def role_names(self) -> ty.Optional[list[str]]:
        """Return a list of user's role names associated with the auth request.

        :returns: a list of strings of role names
        """
        raise NotImplementedError()

    @property
    def domain_name(self) -> ty.Optional[str]:
        """Return the domain name associated with the auth request.

        :returns: str or None (if no domain associated with the token)
        """
        raise NotImplementedError()

    @property
    def domain_id(self) -> ty.Optional[str]:
        """Return the domain id associated with the auth request.

        :returns: str or None (if no domain associated with the token)
        """
        raise NotImplementedError()

    @property
    def project_name(self) -> ty.Optional[str]:
        """Return the project name associated with the auth request.

        :returns: str or None (if no project associated with the token)
        """
        raise NotImplementedError()

    @property
    def tenant_name(self) -> ty.Optional[str]:
        """Synonym for project_name."""
        return self.project_name

    @property
    def scoped(self) -> bool:
        """Return true if the auth token was scoped.

        Returns true if scoped to a tenant(project) or domain,
        and contains a populated service catalog.

        This is deprecated, use project_scoped instead.

        :returns: bool
        """
        return self.project_scoped or self.domain_scoped or self.system_scoped

    @property
    def project_scoped(self) -> bool:
        """Return true if the auth token was scoped to a tenant (project).

        :returns: bool
        """
        return bool(self.project_id)

    @property
    def domain_scoped(self) -> bool:
        """Return true if the auth token was scoped to a domain.

        :returns: bool
        """
        raise NotImplementedError()

    @property
    def system_scoped(self) -> bool:
        """Return true if the auth token was scoped to the system.

        :returns: bool
        """
        raise NotImplementedError()

    @property
    def trust_id(self) -> ty.Optional[str]:
        """Return the trust id associated with the auth request.

        :returns: str or None (if no trust associated with the token)
        """
        raise NotImplementedError()

    @property
    def trust_scoped(self) -> bool:
        """Return true if the auth token was scoped from a delegated trust.

        The trust delegation is via the OS-TRUST v3 extension.

        :returns: bool
        """
        raise NotImplementedError()

    @property
    def trustee_user_id(self) -> ty.Optional[str]:
        """Return the trustee user id associated with a trust.

        :returns: str or None (if no trust associated with the token)
        """
        raise NotImplementedError()

    @property
    def trustor_user_id(self) -> ty.Optional[str]:
        """Return the trustor user id associated with a trust.

        :returns: str or None (if no trust associated with the token)
        """
        raise NotImplementedError()

    @property
    def project_id(self) -> ty.Optional[str]:
        """Return the project ID associated with the auth request.

        This returns None if the auth token wasn't scoped to a project.

        :returns: str or None (if no project associated with the token)
        """
        raise NotImplementedError()

    @property
    def tenant_id(self) -> ty.Optional[str]:
        """Synonym for project_id."""
        return self.project_id

    @property
    def project_domain_id(self) -> ty.Optional[str]:
        """Return the project's domain id associated with the auth request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def project_domain_name(self) -> ty.Optional[str]:
        """Return the project's domain name associated with the auth request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def oauth_access_token_id(self) -> ty.Optional[str]:
        """Return the access token ID if OAuth authentication used.

        :returns: str or None.
        """
        raise NotImplementedError()

    @property
    def oauth_consumer_id(self) -> ty.Optional[str]:
        """Return the consumer ID if OAuth authentication used.

        :returns: str or None.
        """
        raise NotImplementedError()

    @property
    def is_federated(self) -> bool:
        """Return true if federation was used to get the token.

        :returns: boolean
        """
        raise NotImplementedError()

    @property
    def is_admin_project(self) -> bool:
        """Return true if the current project scope is the admin project.

        For backwards compatibility purposes if there is nothing specified in
        the token we always assume we are in the admin project, so this will
        default to True.

        :returns boolean
        """
        raise NotImplementedError()

    @property
    def audit_id(self) -> ty.Optional[str]:
        """Return the audit ID if present.

        :returns: str or None.
        """
        raise NotImplementedError()

    @property
    def audit_chain_id(self) -> ty.Optional[str]:
        """Return the audit chain ID if present.

        In the event that a token was rescoped then this ID will be the
        :py:attr:`audit_id` of the initial token. Returns None if no value
        present.

        :returns: str or None.
        """
        raise NotImplementedError()

    @property
    def initial_audit_id(self) -> ty.Optional[str]:
        """The audit ID of the initially requested token.

        This is the :py:attr:`audit_chain_id` if present or the
        :py:attr:`audit_id`.
        """
        return self.audit_chain_id or self.audit_id

    @property
    def service_providers(
        self,
    ) -> ty.Optional[service_providers.ServiceProviders]:
        """Return an object representing the list of trusted service providers.

        Used for Keystone2Keystone federating-out.

        :returns: :py:class:`keystoneauth1.service_providers.ServiceProviders`
                  or None
        """
        raise NotImplementedError()

    @property
    def bind(self) -> ty.Optional[dict[str, ty.Any]]:
        """Information about external mechanisms the token is bound to.

        If a token is bound to an external authentication mechanism it can only
        be used in conjunction with that mechanism. For example if bound to a
        kerberos principal it may only be accepted if there is also kerberos
        authentication performed on the request.

        :returns: A dictionary or None. The key will be the bind type the value
                  is a dictionary that is specific to the format of the bind
                  type. Returns None if there is no bind information in the
                  token.
        """
        raise NotImplementedError()

    @property
    def project_is_domain(self) -> ty.Optional[bool]:
        """Return if a project act as a domain.

        :returns: bool
        """
        raise NotImplementedError()


class AccessInfoV2(AccessInfo):
    """An object for encapsulating raw v2 auth token from identity service."""

    version = 'v2.0'
    _service_catalog_class = service_catalog.ServiceCatalogV2
    _data: types.TokenResponseV2

    def has_service_catalog(self) -> bool:
        return 'serviceCatalog' in self._data['access']

    @property
    def _token(self) -> types.TokenV2:
        return self._data['access']['token']

    @property
    def auth_token(self) -> ty.Optional[str]:
        set_token = super().auth_token
        return set_token or self._token.get('id')

    @property
    def expires(self) -> ty.Optional[datetime.datetime]:
        return utils.parse_isotime(self._token['expires'])

    @property
    def issued(self) -> ty.Optional[datetime.datetime]:
        return utils.parse_isotime(self._token['issued_at'])

    @property
    def _user(self) -> types.UserV2:
        return self._data['access']['user']

    @property
    def username(self) -> ty.Optional[str]:
        return self._user.get('name') or self._user.get('username')

    @property
    def user_id(self) -> ty.Optional[str]:
        return self._user.get('id')

    @property
    def user_domain_id(self) -> ty.Optional[str]:
        return None

    @property
    def user_domain_name(self) -> ty.Optional[str]:
        return None

    @property
    def role_ids(self) -> ty.Optional[list[str]]:
        metadata = self._data['access'].get('metadata', {})
        return metadata.get('roles', [])

    @property
    def role_names(self) -> ty.Optional[list[str]]:
        return [r['name'] for r in self._user.get('roles', [])]

    @property
    def domain_name(self) -> ty.Optional[str]:
        return None

    @property
    def domain_id(self) -> ty.Optional[str]:
        return None

    @property
    def project_name(self) -> ty.Optional[str]:
        if 'tenant' in self._token:
            return self._token['tenant'].get('name')

        # pre grizzly
        if 'tenantName' in self._user:
            return self._user['tenantName']

        # pre diablo, keystone only provided a tenantId
        if 'tenantId' in self._token:
            return self._token['tenantId']  # type: ignore

        return None

    @property
    def domain_scoped(self) -> bool:
        return False

    @property
    def system_scoped(self) -> bool:
        return False

    @property
    def _trust(self) -> ty.Optional[types.TrustV2]:
        return self._data['access'].get('trust')

    @property
    def trust_id(self) -> ty.Optional[str]:
        return self._trust and self._trust['id']

    @property
    def trust_scoped(self) -> bool:
        return bool(self._trust)

    @property
    def trustee_user_id(self) -> ty.Optional[str]:
        return self._trust and self._trust['trustee_user_id']

    @property
    def trustor_user_id(self) -> ty.Optional[str]:
        # this information is not available in the v2 token bug: #1331882
        return None

    @property
    def project_id(self) -> ty.Optional[str]:
        if 'tenant' in self._token:
            return self._token['tenant'].get('id')

        # pre grizzly
        if 'tenantId' in self._user:
            return self._user['tenantId']

        # pre diablo, keystone only provided a tenantId
        if 'tenantId' in self._token:
            return self._token['tenantId']  # type: ignore

        return None

    @property
    def project_is_domain(self) -> ty.Optional[bool]:
        return False

    @property
    def project_domain_id(self) -> ty.Optional[str]:
        return None

    @property
    def project_domain_name(self) -> ty.Optional[str]:
        return None

    @property
    def oauth_access_token_id(self) -> ty.Optional[str]:
        return None

    @property
    def oauth_consumer_id(self) -> ty.Optional[str]:
        return None

    @property
    def is_federated(self) -> bool:
        return False

    @property
    def is_admin_project(self) -> bool:
        return True

    @property
    def audit_id(self) -> ty.Optional[str]:
        try:
            return self._token.get('audit_ids', [])[0]
        except IndexError:
            return None

    @property
    def audit_chain_id(self) -> ty.Optional[str]:
        try:
            return self._token.get('audit_ids', [])[1]
        except IndexError:
            return None

    @property
    def service_providers(
        self,
    ) -> ty.Optional[service_providers.ServiceProviders]:
        return None

    @property
    def bind(self) -> ty.Optional[dict[str, ty.Any]]:
        return self._token.get('bind')


class AccessInfoV3(AccessInfo):
    """An object encapsulating raw v3 auth token from identity service."""

    version = 'v3'
    _service_catalog_class = service_catalog.ServiceCatalogV3
    _data: types.TokenResponseV3

    @property
    def _token(self) -> types.TokenV3:
        return self._data['token']

    def has_service_catalog(self) -> bool:
        return 'catalog' in self._token

    @property
    def expires(self) -> ty.Optional[datetime.datetime]:
        return utils.parse_isotime(self._token['expires_at'])

    @property
    def issued(self) -> ty.Optional[datetime.datetime]:
        return utils.parse_isotime(self._token['issued_at'])

    @property
    def _user(self) -> types.UserV3:
        return self._token['user']

    @property
    def username(self) -> ty.Optional[str]:
        return self._user['name']

    @property
    def user_id(self) -> ty.Optional[str]:
        return self._user['id']

    @property
    def _user_domain(self) -> types.UserDomainV3:
        return self._user['domain']

    @property
    def user_domain_id(self) -> ty.Optional[str]:
        return self._user['domain']['id']

    @property
    def user_domain_name(self) -> ty.Optional[str]:
        return self._user['domain']['name']

    @property
    def role_ids(self) -> ty.Optional[list[str]]:
        return [r['id'] for r in self._token.get('roles', [])]

    @property
    def role_names(self) -> ty.Optional[list[str]]:
        return [r['name'] for r in self._token.get('roles', [])]

    @property
    def system(self) -> ty.Optional[types.SystemV3]:
        return self._token.get('system')

    @property
    def _domain(self) -> ty.Optional[types.DomainV3]:
        # only present for domain-scoped tokens
        return self._token.get('domain')

    @property
    def domain_name(self) -> ty.Optional[str]:
        return self._domain and self._domain['name']

    @property
    def domain_id(self) -> ty.Optional[str]:
        return self._domain and self._domain['id']

    @property
    def _project(self) -> ty.Optional[types.ProjectV3]:
        # only present for project-scoped tokens
        return self._token.get('project')

    @property
    def project_id(self) -> ty.Optional[str]:
        return self._project and self._project.get('id')

    @property
    def project_name(self) -> ty.Optional[str]:
        return self._project and self._project.get('name')

    @property
    def project_is_domain(self) -> ty.Optional[bool]:
        return self._token.get('is_domain')

    @property
    def _project_domain(self) -> ty.Optional[types.ProjectDomainV3]:
        return self._project and self._project.get('domain')

    @property
    def project_domain_id(self) -> ty.Optional[str]:
        return self._project_domain and self._project_domain['id']

    @property
    def project_domain_name(self) -> ty.Optional[str]:
        return self._project_domain and self._project_domain['name']

    @property
    def domain_scoped(self) -> bool:
        return bool(self._domain)

    @property
    def system_scoped(self) -> bool:
        return bool(self._token.get('system', {}).get('all'))

    @property
    def _trust(self) -> ty.Optional[types.TrustV3]:
        # only present for trust-scoped tokens
        return self._token.get('OS-TRUST:trust')

    @property
    def trust_id(self) -> ty.Optional[str]:
        return self._trust and self._trust['id']

    @property
    def trust_scoped(self) -> bool:
        return bool(self._trust)

    @property
    def trustee_user_id(self) -> ty.Optional[str]:
        return self._trust and self._trust['trustee_user']['id']

    @property
    def trustor_user_id(self) -> ty.Optional[str]:
        return self._trust and self._trust['trustor_user']['id']

    # TODO(stephenfin): Should this be private like every other high-level
    # accessor? As this stands, it can raise KeyError
    @property
    def application_credential(self) -> types.ApplicationCredentialV3:
        return self._token['application_credential']

    @property
    def _application_credential(
        self,
    ) -> ty.Optional[types.ApplicationCredentialV3]:
        # only present if user has authenticated with application credentials
        return self._token.get('application_credential')

    @property
    def application_credential_id(self) -> ty.Optional[str]:
        return (
            self._application_credential
            and self._application_credential.get('id')
        )

    @property
    def application_credential_access_rules(
        self,
    ) -> ty.Optional[list[types.ApplicationCredentialAccessRuleV3]]:
        return (
            self._application_credential
            and self._application_credential.get('access_rules')
        )

    @property
    def _oauth(self) -> ty.Optional[types.OAuth1V3]:
        # only present if user has authenticated with OAuth1
        return self._token.get('OS-OAUTH1')

    @property
    def oauth_access_token_id(self) -> ty.Optional[str]:
        return self._oauth and self._oauth.get('access_token_id')

    @property
    def oauth_consumer_id(self) -> ty.Optional[str]:
        return self._oauth and self._oauth.get('consumer_id')

    @property
    def is_federated(self) -> bool:
        return 'OS-FEDERATION' in self._user

    @property
    def is_admin_project(self) -> bool:
        return bool(self._token.get('is_admin_project', True))

    @property
    def audit_id(self) -> ty.Optional[str]:
        ret = self._token.get('audit_ids', [])
        return ret[0] if ret else None

    @property
    def audit_chain_id(self) -> ty.Optional[str]:
        ret = self._token.get('audit_ids', [])
        return ret[1] if len(ret) > 1 else None

    @property
    def service_providers(
        self,
    ) -> ty.Optional[service_providers.ServiceProviders]:
        if not self._service_providers:
            self._service_providers = (
                service_providers.ServiceProviders.from_token(self._data)
            )

        return self._service_providers

    @property
    def bind(self) -> ty.Optional[dict[str, ty.Any]]:
        return self._token.get('bind')

    # TODO(stephenfin): Should this be private like every other high-level
    # accessor? As this stands, it can raise KeyError
    @property
    def oauth2_credential(self) -> types.OAuth2V3:
        return self._token['oauth2_credential']

    @property
    def _oauth2_credential(self) -> ty.Optional[types.OAuth2V3]:
        return self._token.get('oauth2_credential')

    @property
    def oauth2_credential_thumbprint(self) -> ty.Optional[str]:
        return self._oauth2_credential and self._oauth2_credential.get(
            'x5t#S256'
        )
