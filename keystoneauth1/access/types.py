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

from typing import Any, NotRequired, TypedDict

# Identity V2 auth fields


class TenantV2(TypedDict):
    description: NotRequired[str | None]
    enabled: NotRequired[bool]
    id: str
    name: str


class TokenV2(TypedDict):
    audit_ids: list[str]
    bind: NotRequired[dict[str, Any]]
    expires: str
    id: str
    issued_at: NotRequired[str]
    tenant: NotRequired[TenantV2]


class EndpointV2(TypedDict):
    adminURL: str
    region: str
    internalURL: str
    id: str
    publicURL: str


class CatalogServiceV2(TypedDict):
    endpoints: list[EndpointV2]
    endpoints_links: list[Any]
    type: str
    name: str


class RoleV2(TypedDict):
    name: str


class UserV2(TypedDict):
    id: str
    name: str
    role_links: list[Any]
    roles: list[RoleV2]
    tenantId: NotRequired[str]
    tenantName: NotRequired[str]
    username: str


class MetadataV2(TypedDict):
    is_admin: int
    roles: list[str]


class TrustV2(TypedDict):
    id: str
    impersonation: bool
    trustee_user_id: str
    trustor_user_id: str


class AccessV2(TypedDict):
    token: TokenV2
    serviceCatalog: NotRequired[list[CatalogServiceV2]]
    user: UserV2
    metadata: NotRequired[MetadataV2]
    trust: NotRequired[TrustV2]


class TokenResponseV2(TypedDict):
    access: AccessV2


# Identity V3 auth fields


class EndpointV3(TypedDict):
    id: str
    interface: str
    region: str
    region_id: str
    url: str


class ServiceV3(TypedDict):
    endpoints: list[EndpointV3]
    id: str
    name: str
    type: str


class ProjectDomainV3(TypedDict):
    id: str
    name: str


class ProjectV3(TypedDict):
    domain: ProjectDomainV3
    id: str
    name: str


class DomainV3(TypedDict):
    id: str
    name: str


class UserDomainV3(TypedDict):
    id: str
    name: str


class FederationGroupV3(TypedDict):
    id: str


class FederationProviderV3(TypedDict):
    id: str


class FederationProtocolV3(TypedDict):
    id: str


class FederationV3(TypedDict):
    groups: list[FederationGroupV3]
    identity_provider: FederationProviderV3
    protocol: FederationProtocolV3


UserV3 = TypedDict(
    'UserV3',
    {
        'domain': UserDomainV3,
        'id': str,
        'name': str,
        'password_expires_at': NotRequired[str],
        'OS-FEDERATION': NotRequired[FederationV3],
    },
)


class RoleV3(TypedDict):
    id: str
    name: str


class ApplicationCredentialAccessRuleV3(TypedDict):
    id: str


class ApplicationCredentialV3(TypedDict):
    access_rules: NotRequired[list[ApplicationCredentialAccessRuleV3]]
    id: str
    name: str
    restricted: bool


class ServiceProviderV3(TypedDict):
    auth_url: str
    id: str
    sp_url: str


class TrustorUser(TypedDict):
    id: str


class TrusteeUser(TypedDict):
    id: str


class TrustV3(TypedDict):
    id: str
    impersonation: bool
    trustee_user: TrusteeUser
    trustor_user: TrustorUser


class OAuth1V3(TypedDict):
    access_token_id: str
    consumer_id: str


OAuth2V3 = TypedDict('OAuth2V3', {'x5t#S256': str})


class SystemV3(TypedDict):
    all: bool


TokenV3 = TypedDict(
    'TokenV3',
    {
        'application_credential': NotRequired[ApplicationCredentialV3],
        'audit_ids': list[str],
        'bind': NotRequired[dict[str, Any]],
        'catalog': NotRequired[list[ServiceV3]],
        'domain': NotRequired[DomainV3],
        'expires_at': str,
        'is_admin_project': NotRequired[bool],
        'is_domain': NotRequired[bool],
        'issued_at': str,
        'methods': list[str],
        'oauth2_credential': NotRequired[OAuth2V3],
        'project': ProjectV3,
        'roles': list[RoleV3],
        'service_providers': NotRequired[list[ServiceProviderV3]],
        'system': NotRequired[SystemV3],
        'user': UserV3,
        'OS-OAUTH1': NotRequired[OAuth1V3],
        'OS-TRUST:trust': NotRequired[TrustV3],
    },
)


class TokenResponseV3(TypedDict):
    token: TokenV3
