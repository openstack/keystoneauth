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

import datetime
import typing as ty
import uuid

import typing_extensions as ty_ext

from keystoneauth1 import _utils
from keystoneauth1.fixture import exception


class V3Domain(ty.TypedDict, total=False):
    id: str
    name: str


class V3Project(ty.TypedDict, total=False):
    id: str
    name: str
    domain: V3Domain
    is_domain: bool


class V3User(ty.TypedDict):
    id: str
    name: str
    domain: V3Domain


class V3Role(ty.TypedDict):
    id: str
    name: str


class V3Endpoint(ty.TypedDict):
    id: str
    interface: str
    url: str
    region: str | None
    region_id: str | None


class V3Service(ty.TypedDict):
    id: str
    type: str
    name: ty_ext.NotRequired[str]
    endpoints: ty_ext.NotRequired[list[V3Endpoint]]


class V3System(ty.TypedDict):
    all: bool


class V3Trust(ty.TypedDict, total=False):
    id: str
    impersonation: bool
    trustee_user_id: str
    trustor_user_id: str


class V3ApplicationCredential(ty.TypedDict, total=False):
    id: str
    access_rules: list[dict[str, ty.Any]]


class V3OAuth(ty.TypedDict, total=False):
    access_token_id: str
    consumer_id: str


class V3ServiceProvider(ty.TypedDict):
    id: str
    auth_url: str
    sp_url: str


class V3TokenData(ty.TypedDict, total=False):
    expires_at: str
    issued_at: str
    methods: list[str]
    user: V3User
    project: V3Project
    domain: V3Domain
    system: V3System
    roles: list[V3Role]
    catalog: list[V3Service]
    bind: dict[str, ty.Any]
    audit_ids: list[str]
    service_providers: list[V3ServiceProvider]
    is_admin_project: bool
    is_domain: bool
    oauth2_thumbprint: str
    oauth2_credential: dict[str, ty.Any]
    application_credential: dict[str, ty.Any]


class V3TokenDataWithNamespaces(V3TokenData, total=False):
    pass


V3TokenDict = dict[str, ty.Any]


class V3TokenRoot(ty.TypedDict):
    token: V3TokenData


class _Service(dict[str, ty.Any]):
    """One of the services that exist in the catalog.

    You use this by adding a service to a token which returns an instance of
    this object and then you can add_endpoints to the service.
    """

    def add_endpoint(
        self,
        interface: str,
        url: str,
        region: str | None = None,
        id: str | None = None,
    ) -> V3Endpoint:
        data: V3Endpoint = {
            'id': id or uuid.uuid4().hex,
            'interface': interface,
            'url': url,
            'region': region,
            'region_id': region,
        }
        endpoints = self.setdefault('endpoints', [])
        endpoints.append(data)
        return data

    def add_standard_endpoints(
        self,
        public: str | None = None,
        admin: str | None = None,
        internal: str | None = None,
        region: str | None = None,
    ) -> list[V3Endpoint]:
        ret = []

        if public:
            ret.append(self.add_endpoint('public', public, region=region))
        if admin:
            ret.append(self.add_endpoint('admin', admin, region=region))
        if internal:
            ret.append(self.add_endpoint('internal', internal, region=region))

        return ret


class Token(dict[str, ty.Any]):
    """A V3 Keystone token that can be used for testing.

    This object is designed to allow clients to generate a correct V3 token for
    use in there test code. It should prevent clients from having to know the
    correct token format and allow them to test the portions of token handling
    that matter to them and not copy and paste sample.
    """

    def __init__(
        self,
        expires: datetime.datetime | str | None = None,
        issued: datetime.datetime | str | None = None,
        user_id: str | None = None,
        user_name: str | None = None,
        user_domain_id: str | None = None,
        user_domain_name: str | None = None,
        methods: list[str] | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        trust_id: str | None = None,
        trust_impersonation: bool | None = None,
        trustee_user_id: str | None = None,
        trustor_user_id: str | None = None,
        application_credential_id: str | None = None,
        application_credential_access_rules: list[dict[str, ty.Any]]
        | None = None,
        oauth_access_token_id: str | None = None,
        oauth_consumer_id: str | None = None,
        audit_id: str | None = None,
        audit_chain_id: str | None = None,
        is_admin_project: bool | None = None,
        project_is_domain: bool | None = None,
        oauth2_thumbprint: str | None = None,
    ) -> None:
        super().__init__()

        self.user_id = user_id or uuid.uuid4().hex
        self.user_name = user_name or uuid.uuid4().hex
        self.user_domain_id = user_domain_id or uuid.uuid4().hex
        self.user_domain_name = user_domain_name or uuid.uuid4().hex
        self.audit_id = audit_id or uuid.uuid4().hex

        if not methods:
            methods = ['password']
        self.methods.extend(methods)

        if not issued:
            issued = _utils.before_utcnow(minutes=2)

        if isinstance(issued, str):
            self.issued_str = issued
            # If issued is a string, we can't do math on it for expires
            if not expires:
                # Default to 1 hour from now
                expires = _utils.before_utcnow(minutes=2) + datetime.timedelta(
                    hours=1
                )
        else:
            self.issued = issued
            if not expires:
                expires = self.issued + datetime.timedelta(hours=1)

        if isinstance(expires, str):
            self.expires_str = expires
        elif expires is not None:
            self.expires = expires

        if (
            project_id
            or project_name
            or project_domain_id
            or project_domain_name
        ):
            self.set_project_scope(
                id=project_id,
                name=project_name,
                domain_id=project_domain_id,
                domain_name=project_domain_name,
                is_domain=project_is_domain,
            )

        if domain_id or domain_name:
            self.set_domain_scope(id=domain_id, name=domain_name)

        if (
            trust_id
            or (trust_impersonation is not None)
            or trustee_user_id
            or trustor_user_id
        ):
            self.set_trust_scope(
                id=trust_id,
                impersonation=trust_impersonation or False,
                trustee_user_id=trustee_user_id,
                trustor_user_id=trustor_user_id,
            )

        if application_credential_id:
            self.set_application_credential(
                application_credential_id,
                access_rules=application_credential_access_rules,
            )

        if oauth_access_token_id or oauth_consumer_id:
            self.set_oauth(
                access_token_id=oauth_access_token_id,
                consumer_id=oauth_consumer_id,
            )

        if audit_chain_id:
            self.audit_chain_id = audit_chain_id

        if is_admin_project is not None:
            self.is_admin_project = is_admin_project

        if oauth2_thumbprint:
            self.oauth2_thumbprint = oauth2_thumbprint

    @property
    def root(self) -> dict[str, ty.Any]:
        if 'token' not in self:
            self['token'] = {
                'methods': [],
                'user': {
                    'id': '',
                    'name': '',
                    'domain': {'id': '', 'name': ''},
                },
            }
        root: dict[str, ty.Any] = self['token']
        return root

    @property
    def expires_str(self) -> str | None:
        return self.root.get('expires_at')

    @expires_str.setter
    def expires_str(self, value: str) -> None:
        self.root['expires_at'] = value

    @property
    def expires(self) -> datetime.datetime:
        assert self.expires_str is not None
        return _utils.parse_isotime(self.expires_str)

    @expires.setter
    def expires(self, value: datetime.datetime) -> None:
        self.expires_str = value.isoformat()

    @property
    def issued_str(self) -> str | None:
        return self.root.get('issued_at')

    @issued_str.setter
    def issued_str(self, value: str) -> None:
        self.root['issued_at'] = value

    @property
    def issued(self) -> datetime.datetime:
        assert self.issued_str is not None
        return _utils.parse_isotime(self.issued_str)

    @issued.setter
    def issued(self, value: datetime.datetime) -> None:
        self.issued_str = value.isoformat()

    @property
    def _user(self) -> dict[str, ty.Any]:
        user: dict[str, ty.Any] = self.root['user']
        return user

    @property
    def user_id(self) -> str | None:
        return self._user.get('id')

    @user_id.setter
    def user_id(self, value: str) -> None:
        self._user['id'] = value

    @property
    def user_name(self) -> str | None:
        return self._user.get('name')

    @user_name.setter
    def user_name(self, value: str) -> None:
        self._user['name'] = value

    @property
    def _user_domain(self) -> dict[str, ty.Any]:
        domain: dict[str, ty.Any] = self._user['domain']
        return domain

    @_user_domain.setter
    def _user_domain(self, domain: dict[str, ty.Any]) -> None:
        self._user['domain'] = domain

    @property
    def user_domain_id(self) -> str | None:
        return self._user_domain.get('id')

    @user_domain_id.setter
    def user_domain_id(self, value: str) -> None:
        self._user_domain['id'] = value

    @property
    def user_domain_name(self) -> str | None:
        return self._user_domain.get('name')

    @user_domain_name.setter
    def user_domain_name(self, value: str) -> None:
        self._user_domain['name'] = value

    @property
    def methods(self) -> list[str]:
        methods: list[str] = self.root['methods']
        return methods

    @property
    def project_id(self) -> str | None:
        project: V3Project = self.root.get('project', {})
        return project.get('id')

    @project_id.setter
    def project_id(self, value: str) -> None:
        self.root.setdefault('project', {})['id'] = value

    @property
    def project_is_domain(self) -> bool | None:
        return self.root.get('is_domain')

    @project_is_domain.setter
    def project_is_domain(self, value: bool) -> None:
        self.root['is_domain'] = value

    @property
    def project_name(self) -> str | None:
        project: V3Project = self.root.get('project', {})
        return project.get('name')

    @project_name.setter
    def project_name(self, value: str) -> None:
        self.root.setdefault('project', {})['name'] = value

    @property
    def project_domain_id(self) -> str | None:
        project: V3Project = self.root.get('project', {})
        domain = project.get('domain')
        return domain.get('id') if domain is not None else None

    @project_domain_id.setter
    def project_domain_id(self, value: str) -> None:
        project = self.root.setdefault('project', {})
        project.setdefault('domain', {})['id'] = value

    @property
    def project_domain_name(self) -> str | None:
        project: V3Project = self.root.get('project', {})
        domain = project.get('domain')
        return domain.get('name') if domain is not None else None

    @project_domain_name.setter
    def project_domain_name(self, value: str) -> None:
        project = self.root.setdefault('project', {})
        project.setdefault('domain', {})['name'] = value

    @property
    def domain_id(self) -> str | None:
        domain: V3Domain = self.root.get('domain', {})
        return domain.get('id')

    @domain_id.setter
    def domain_id(self, value: str) -> None:
        self.root.setdefault('domain', {})['id'] = value

    @property
    def domain_name(self) -> str | None:
        domain: V3Domain = self.root.get('domain', {})
        return domain.get('name')

    @domain_name.setter
    def domain_name(self, value: str) -> None:
        self.root.setdefault('domain', {})['name'] = value

    @property
    def system(self) -> dict[str, ty.Any]:
        system: dict[str, ty.Any] = self.root.get('system', {})
        return system

    @system.setter
    def system(self, value: dict[str, ty.Any]) -> None:
        self.root['system'] = value

    @property
    def trust_id(self) -> str | None:
        trust: dict[str, ty.Any] = self.root.get('OS-TRUST:trust', {})
        result: str | None = trust.get('id')
        return result

    @trust_id.setter
    def trust_id(self, value: str) -> None:
        self.root.setdefault('OS-TRUST:trust', {})['id'] = value

    @property
    def trust_impersonation(self) -> bool | None:
        trust: dict[str, ty.Any] = self.root.get('OS-TRUST:trust', {})
        result: bool | None = trust.get('impersonation')
        return result

    @trust_impersonation.setter
    def trust_impersonation(self, value: bool) -> None:
        self.root.setdefault('OS-TRUST:trust', {})['impersonation'] = value

    @property
    def trustee_user_id(self) -> str | None:
        trust: dict[str, ty.Any] = self.root.get('OS-TRUST:trust', {})
        trustee_user: dict[str, str | None] = trust.get('trustee_user', {})
        return trustee_user.get('id')

    @trustee_user_id.setter
    def trustee_user_id(self, value: str) -> None:
        trust = self.root.setdefault('OS-TRUST:trust', {})
        trust.setdefault('trustee_user', {})['id'] = value

    @property
    def trustor_user_id(self) -> str | None:
        trust: dict[str, ty.Any] = self.root.get('OS-TRUST:trust', {})
        trustor_user: dict[str, str | None] = trust.get('trustor_user', {})
        return trustor_user.get('id')

    @trustor_user_id.setter
    def trustor_user_id(self, value: str) -> None:
        trust = self.root.setdefault('OS-TRUST:trust', {})
        trust.setdefault('trustor_user', {})['id'] = value

    @property
    def application_credential_id(self) -> str | None:
        ac: dict[str, ty.Any] = self.root.get('application_credential', {})
        result: str | None = ac.get('id')
        return result

    @application_credential_id.setter
    def application_credential_id(self, value: str) -> None:
        application_credential = self.root.setdefault(
            'application_credential', {}
        )
        application_credential['id'] = value

    @property
    def application_credential_access_rules(
        self,
    ) -> list[dict[str, ty.Any]] | None:
        ac: dict[str, ty.Any] = self.root.get('application_credential', {})
        result: list[dict[str, ty.Any]] | None = ac.get('access_rules')
        return result

    @application_credential_access_rules.setter
    def application_credential_access_rules(
        self, value: list[dict[str, ty.Any]]
    ) -> None:
        application_credential = self.root.setdefault(
            'application_credential', {}
        )
        application_credential['access_rules'] = value

    @property
    def oauth_access_token_id(self) -> str | None:
        oauth: dict[str, ty.Any] = self.root.get('OS-OAUTH1', {})
        result: str | None = oauth.get('access_token_id')
        return result

    @oauth_access_token_id.setter
    def oauth_access_token_id(self, value: str) -> None:
        self.root.setdefault('OS-OAUTH1', {})['access_token_id'] = value

    @property
    def oauth_consumer_id(self) -> str | None:
        oauth: dict[str, ty.Any] = self.root.get('OS-OAUTH1', {})
        result: str | None = oauth.get('consumer_id')
        return result

    @oauth_consumer_id.setter
    def oauth_consumer_id(self, value: str) -> None:
        self.root.setdefault('OS-OAUTH1', {})['consumer_id'] = value

    @property
    def audit_id(self) -> str | None:
        audit_ids: list[str] = self.root.get('audit_ids', [])
        try:
            return audit_ids[0]
        except IndexError:
            return None

    @audit_id.setter
    def audit_id(self, value: str) -> None:
        audit_chain_id = self.audit_chain_id
        if audit_chain_id:
            lval: list[str] = [value, audit_chain_id]
        else:
            lval = [value]
        self.root['audit_ids'] = lval

    @property
    def audit_chain_id(self) -> str | None:
        audit_ids: list[str] = self.root.get('audit_ids', [])
        try:
            return audit_ids[1]
        except IndexError:
            return None

    @audit_chain_id.setter
    def audit_chain_id(self, value: str) -> None:
        self.root['audit_ids'] = [self.audit_id, value]

    @property
    def role_ids(self) -> list[str]:
        return [r['id'] for r in self.root.get('roles', [])]

    @property
    def role_names(self) -> list[str]:
        return [r['name'] for r in self.root.get('roles', [])]

    @property
    def is_admin_project(self) -> bool | None:
        return self.root.get('is_admin_project')

    @is_admin_project.setter
    def is_admin_project(self, value: bool) -> None:
        self.root['is_admin_project'] = value

    @is_admin_project.deleter
    def is_admin_project(self) -> None:
        self.root.pop('is_admin_project', None)

    @property
    def oauth2_thumbprint(self) -> str | None:
        oauth2_cred: dict[str, ty.Any] = self.root.get('oauth2_credential', {})
        result: str | None = oauth2_cred.get('x5t#S256')
        return result

    @oauth2_thumbprint.setter
    def oauth2_thumbprint(self, value: str) -> None:
        self.root.setdefault('oauth2_credential', {})['x5t#S256'] = value

    @property
    def oauth2_credential(self) -> dict[str, ty.Any] | None:
        return self.root.get('oauth2_credential')

    def validate(self) -> None:
        project = self.root.get('project')
        domain = self.root.get('domain')
        system = self.root.get('system')
        trust = self.root.get('OS-TRUST:trust')
        catalog = self.root.get('catalog')
        roles = self.root.get('roles')
        scoped = project or domain or trust

        if sum((bool(project), bool(domain), bool(trust), bool(system))) > 1:
            msg = 'You cannot scope to multiple targets'
            raise exception.FixtureValidationError(msg)

        if catalog and not scoped:
            msg = 'You cannot have a service catalog on an unscoped token'
            raise exception.FixtureValidationError(msg)

        if scoped and not self._user.get('roles'):
            msg = 'You must have roles on a token to scope it'
            raise exception.FixtureValidationError(msg)

        if bool(scoped) != bool(roles):
            msg = 'You must be scoped to have roles and vice-versa'
            raise exception.FixtureValidationError(msg)

    def add_role(
        self, name: str | None = None, id: str | None = None
    ) -> dict[str, str]:
        if 'roles' not in self.root:
            self.root['roles'] = []
        roles = self.root['roles']
        data = {'id': id or uuid.uuid4().hex, 'name': name or uuid.uuid4().hex}
        roles.append(data)
        return data

    def add_service(
        self, type: str, name: str | None = None, id: str | None = None
    ) -> _Service:
        service = _Service(type=type, id=id or uuid.uuid4().hex)
        if name:
            service['name'] = name
        if 'catalog' not in self.root:
            self.root['catalog'] = []
        self.root['catalog'].append(service)
        return service

    def remove_service(self, type: str) -> None:
        self.root.setdefault('catalog', [])
        self.root['catalog'] = [
            f for f in self.root.setdefault('catalog', []) if f['type'] != type
        ]

    def set_project_scope(
        self,
        id: str | None = None,
        name: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        is_domain: bool | None = None,
    ) -> None:
        self.project_id = id or uuid.uuid4().hex
        self.project_name = name or uuid.uuid4().hex
        self.project_domain_id = domain_id or uuid.uuid4().hex
        self.project_domain_name = domain_name or uuid.uuid4().hex

        if is_domain is not None:
            self.project_is_domain = is_domain

    def set_domain_scope(
        self, id: str | None = None, name: str | None = None
    ) -> None:
        self.domain_id = id or uuid.uuid4().hex
        self.domain_name = name or uuid.uuid4().hex

    def set_system_scope(self) -> None:
        # NOTE(lbragstad): In the future it might be possible to scope a token
        # to a subset of the entire system (e.g. a specific service, region, or
        # service within a region). Until then, the only system scope is the
        # entire system.
        self.system = {'all': True}

    def set_trust_scope(
        self,
        id: str | None = None,
        impersonation: bool = False,
        trustee_user_id: str | None = None,
        trustor_user_id: str | None = None,
    ) -> None:
        self.trust_id = id or uuid.uuid4().hex
        self.trust_impersonation = impersonation
        self.trustee_user_id = trustee_user_id or uuid.uuid4().hex
        self.trustor_user_id = trustor_user_id or uuid.uuid4().hex

    def set_oauth(
        self,
        access_token_id: str | None = None,
        consumer_id: str | None = None,
    ) -> None:
        self.oauth_access_token_id = access_token_id or uuid.uuid4().hex
        self.oauth_consumer_id = consumer_id or uuid.uuid4().hex

    def set_application_credential(
        self,
        application_credential_id: str,
        access_rules: list[dict[str, ty.Any]] | None = None,
    ) -> None:
        self.application_credential_id = application_credential_id
        if access_rules is not None:
            self.application_credential_access_rules = access_rules

    @property
    def service_providers(self) -> list[dict[str, str]] | None:
        return self.root.get('service_providers')

    def add_service_provider(
        self, sp_id: str, sp_auth_url: str, sp_url: str
    ) -> dict[str, str]:
        if 'service_providers' not in self.root:
            self.root['service_providers'] = []
        _service_providers = self.root['service_providers']
        sp = {'id': sp_id, 'auth_url': sp_auth_url, 'sp_url': sp_url}
        _service_providers.append(sp)
        return sp

    def set_bind(self, name: str, data: ty.Any) -> None:
        self.root.setdefault('bind', {})[name] = data


class V3FederationToken(Token):
    """A V3 Keystone Federation token that can be used for testing.

    Similar to V3Token, this object is designed to allow clients to generate
    a correct V3 federation token for use in test code.
    """

    FEDERATED_DOMAIN_ID = 'Federated'

    def __init__(
        self,
        methods: list[str] | None = None,
        identity_provider: str | None = None,
        protocol: str | None = None,
        groups: list[str] | None = None,
    ) -> None:
        methods = methods or ['saml2']
        super().__init__(methods=methods)
        self._user_domain = {'id': V3FederationToken.FEDERATED_DOMAIN_ID}
        self.add_federation_info_to_user(identity_provider, protocol, groups)

    def add_federation_info_to_user(
        self,
        identity_provider: str | None = None,
        protocol: str | None = None,
        groups: list[str] | None = None,
    ) -> None:
        os_federation_data = {
            "identity_provider": identity_provider or uuid.uuid4().hex,
            "protocol": protocol or uuid.uuid4().hex,
            "groups": groups or [uuid.uuid4().hex],
        }

        if 'OS-FEDERATION' not in self._user:
            self._user['OS-FEDERATION'] = {}
        self._user['OS-FEDERATION'].update(os_federation_data)
