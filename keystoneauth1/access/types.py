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

import typing as ty

import typing_extensions as ty_ext

# Identity V2 auth fields


class TenantV2(ty.TypedDict):
    description: ty_ext.NotRequired[ty.Optional[str]]
    enabled: ty_ext.NotRequired[bool]
    id: str
    name: str


class TokenV2(ty.TypedDict):
    audit_ids: list[str]
    bind: ty_ext.NotRequired[dict[str, ty.Any]]
    expires: str
    id: str
    issued_at: ty_ext.NotRequired[str]
    tenant: ty_ext.NotRequired[TenantV2]


class EndpointV2(ty.TypedDict):
    adminURL: str
    region: str
    internalURL: str
    id: str
    publicURL: str


class CatalogServiceV2(ty.TypedDict):
    endpoints: list[EndpointV2]
    endpoints_links: list[ty.Any]
    type: str
    name: str


class RoleV2(ty.TypedDict):
    name: str


class UserV2(ty.TypedDict):
    id: str
    name: str
    role_links: list[ty.Any]
    roles: list[RoleV2]
    tenantId: ty_ext.NotRequired[str]
    tenantName: ty_ext.NotRequired[str]
    username: str


class MetadataV2(ty.TypedDict):
    is_admin: int
    roles: list[str]


class TrustV2(ty.TypedDict):
    id: str
    impersonation: bool
    trustee_user_id: str
    trustor_user_id: str


class AccessV2(ty.TypedDict):
    token: TokenV2
    serviceCatalog: ty_ext.NotRequired[list[CatalogServiceV2]]
    user: UserV2
    metadata: ty_ext.NotRequired[MetadataV2]
    trust: ty_ext.NotRequired[TrustV2]


class TokenResponseV2(ty.TypedDict):
    access: AccessV2


# Identity V3 auth fields


class EndpointV3(ty.TypedDict):
    id: str
    interface: str
    region: str
    region_id: str
    url: str


class ServiceV3(ty.TypedDict):
    endpoints: list[EndpointV3]
    id: str
    name: str
    type: str


class ProjectDomainV3(ty.TypedDict):
    id: str
    name: str


class ProjectV3(ty.TypedDict):
    domain: ProjectDomainV3
    id: str
    name: str


class DomainV3(ty.TypedDict):
    id: str
    name: str


class UserDomainV3(ty.TypedDict):
    id: str
    name: str


class FederationGroupV3(ty.TypedDict):
    id: str


class FederationProviderV3(ty.TypedDict):
    id: str


class FederationProtocolV3(ty.TypedDict):
    id: str


class FederationV3(ty.TypedDict):
    groups: list[FederationGroupV3]
    identity_provider: FederationProviderV3
    protocol: FederationProtocolV3


UserV3 = ty.TypedDict(
    'UserV3',
    {
        'domain': UserDomainV3,
        'id': str,
        'name': str,
        'password_expires_at': ty_ext.NotRequired[str],
        'OS-FEDERATION': ty_ext.NotRequired[FederationV3],
    },
)


class RoleV3(ty.TypedDict):
    id: str
    name: str


class ApplicationCredentialAccessRuleV3(ty.TypedDict):
    id: str


class ApplicationCredentialV3(ty.TypedDict):
    access_rules: ty_ext.NotRequired[list[ApplicationCredentialAccessRuleV3]]
    id: str
    name: str
    restricted: bool


class ServiceProviderV3(ty.TypedDict):
    auth_url: str
    id: str
    sp_url: str


class TrustorUser(ty.TypedDict):
    id: str


class TrusteeUser(ty.TypedDict):
    id: str


class TrustV3(ty.TypedDict):
    id: str
    impersonation: bool
    trustee_user: TrusteeUser
    trustor_user: TrustorUser


class OAuth1V3(ty.TypedDict):
    access_token_id: str
    consumer_id: str


OAuth2V3 = ty.TypedDict('OAuth2V3', {'x5t#S256': str})


class SystemV3(ty.TypedDict):
    all: bool


TokenV3 = ty.TypedDict(
    'TokenV3',
    {
        'application_credential': ty_ext.NotRequired[ApplicationCredentialV3],
        'audit_ids': list[str],
        'bind': ty_ext.NotRequired[dict[str, ty.Any]],
        'catalog': ty_ext.NotRequired[list[ServiceV3]],
        'domain': ty_ext.NotRequired[DomainV3],
        'expires_at': str,
        'is_admin_project': ty_ext.NotRequired[bool],
        'is_domain': ty_ext.NotRequired[bool],
        'issued_at': str,
        'methods': list[str],
        'oauth2_credential': ty_ext.NotRequired[OAuth2V3],
        'project': ProjectV3,
        'roles': list[RoleV3],
        'service_providers': ty_ext.NotRequired[list[ServiceProviderV3]],
        'system': ty_ext.NotRequired[SystemV3],
        'user': UserV3,
        'OS-OAUTH1': ty_ext.NotRequired[OAuth1V3],
        'OS-TRUST:trust': ty_ext.NotRequired[TrustV3],
    },
)


class TokenResponseV3(ty.TypedDict):
    token: TokenV3
