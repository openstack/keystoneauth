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


class V2Role(ty.TypedDict):
    name: str


class V2Endpoint(ty.TypedDict):
    tenantId: str
    publicURL: str
    adminURL: str
    internalURL: str
    region: str | None
    id: str


class V2Service(ty.TypedDict):
    name: str
    type: str
    endpoints: ty_ext.NotRequired[list[V2Endpoint]]


class V2Tenant(ty.TypedDict, total=False):
    id: str
    name: str


class V2Trust(ty.TypedDict, total=False):
    id: str
    trustee_user_id: str


class V2Token(ty.TypedDict):
    id: str
    expires: str
    issued_at: str
    tenant: ty_ext.NotRequired[V2Tenant]
    audit_ids: ty_ext.NotRequired[list[str]]
    bind: ty_ext.NotRequired[dict[str, ty.Any]]


class V2User(ty.TypedDict):
    id: str
    name: str
    roles: ty_ext.NotRequired[list[V2Role]]


class V2Metadata(ty.TypedDict):
    roles: ty_ext.NotRequired[list[str]]


class V2Access(ty.TypedDict):
    token: V2Token
    user: V2User
    metadata: ty_ext.NotRequired[V2Metadata]
    serviceCatalog: ty_ext.NotRequired[list[dict[str, ty.Any]]]
    trust: ty_ext.NotRequired[V2Trust]


class V2TokenRoot(ty.TypedDict):
    access: V2Access


class _Service(dict[str, ty.Any]):
    def add_endpoint(
        self,
        public: str,
        admin: str | None = None,
        internal: str | None = None,
        tenant_id: str | None = None,
        region: str | None = None,
        id: str | None = None,
    ) -> V2Endpoint:
        data: V2Endpoint = {
            'tenantId': tenant_id or uuid.uuid4().hex,
            'publicURL': public,
            'adminURL': admin or public,
            'internalURL': internal or public,
            'region': region,
            'id': id or uuid.uuid4().hex,
        }

        endpoints = self.setdefault('endpoints', [])
        endpoints.append(data)
        return data


class Token(dict[str, ty.Any]):
    """A V2 Keystone token that can be used for testing.

    This object is designed to allow clients to generate a correct V2 token for
    use in there test code. It should prevent clients from having to know the
    correct token format and allow them to test the portions of token handling
    that matter to them and not copy and paste sample.
    """

    def __init__(
        self,
        token_id: str | None = None,
        expires: datetime.datetime | str | None = None,
        issued: datetime.datetime | str | None = None,
        tenant_id: str | None = None,
        tenant_name: str | None = None,
        user_id: str | None = None,
        user_name: str | None = None,
        trust_id: str | None = None,
        trustee_user_id: str | None = None,
        audit_id: str | None = None,
        audit_chain_id: str | None = None,
    ) -> None:
        super().__init__()

        self.token_id = token_id or uuid.uuid4().hex
        self.user_id = user_id or uuid.uuid4().hex
        self.user_name = user_name or uuid.uuid4().hex
        self.audit_id = audit_id or uuid.uuid4().hex

        if not issued:
            issued = _utils.before_utcnow(minutes=2)

        if not expires and isinstance(issued, datetime.datetime):
            expires = issued + datetime.timedelta(hours=1)

        if isinstance(issued, str):
            self.issued_str = issued
        else:
            self.issued = issued

        if isinstance(expires, str):
            self.expires_str = expires
        elif expires is not None:
            self.expires = expires

        if tenant_id or tenant_name:
            self.set_scope(tenant_id, tenant_name)

        if trust_id or trustee_user_id:
            # the trustee_user_id will generally be the same as the user_id as
            # the token is being issued to the trustee
            self.set_trust(
                id=trust_id, trustee_user_id=trustee_user_id or user_id
            )

        if audit_chain_id:
            self.audit_chain_id = audit_chain_id

    @property
    def root(self) -> V2Access:
        if 'access' not in self:
            self['access'] = {
                'token': {'id': '', 'expires': '', 'issued_at': ''},
                'user': {'id': '', 'name': ''},
            }
        access: V2Access = self['access']
        return access

    @property
    def _token(self) -> V2Token:
        return self.root['token']

    @property
    def token_id(self) -> str:
        return self._token['id']

    @token_id.setter
    def token_id(self, value: str) -> None:
        self._token['id'] = value

    @property
    def expires_str(self) -> str:
        return self._token['expires']

    @expires_str.setter
    def expires_str(self, value: str) -> None:
        self._token['expires'] = value

    @property
    def expires(self) -> datetime.datetime:
        return _utils.parse_isotime(self.expires_str)

    @expires.setter
    def expires(self, value: datetime.datetime) -> None:
        self.expires_str = value.isoformat()

    @property
    def issued_str(self) -> str:
        return self._token['issued_at']

    @issued_str.setter
    def issued_str(self, value: str) -> None:
        self._token['issued_at'] = value

    @property
    def issued(self) -> datetime.datetime:
        return _utils.parse_isotime(self.issued_str)

    @issued.setter
    def issued(self, value: datetime.datetime) -> None:
        self.issued_str = value.isoformat()

    @property
    def _user(self) -> V2User:
        return self.root['user']

    @property
    def user_id(self) -> str:
        return self._user['id']

    @user_id.setter
    def user_id(self, value: str) -> None:
        self._user['id'] = value

    @property
    def user_name(self) -> str:
        return self._user['name']

    @user_name.setter
    def user_name(self, value: str) -> None:
        self._user['name'] = value

    @property
    def tenant_id(self) -> str | None:
        return self._token.get('tenant', {}).get('id')

    @tenant_id.setter
    def tenant_id(self, value: str) -> None:
        if 'tenant' not in self._token:
            self._token['tenant'] = {}
        self._token['tenant']['id'] = value

    @property
    def tenant_name(self) -> str | None:
        return self._token.get('tenant', {}).get('name')

    @tenant_name.setter
    def tenant_name(self, value: str) -> None:
        if 'tenant' not in self._token:
            self._token['tenant'] = {}
        self._token['tenant']['name'] = value

    @property
    def _metadata(self) -> V2Metadata:
        if 'metadata' not in self.root:
            self.root['metadata'] = {}
        return self.root['metadata']

    @property
    def trust_id(self) -> str | None:
        return self.root.get('trust', {}).get('id')

    @trust_id.setter
    def trust_id(self, value: str) -> None:
        if 'trust' not in self.root:
            self.root['trust'] = {}
        self.root['trust']['id'] = value

    @property
    def trustee_user_id(self) -> str | None:
        return self.root.get('trust', {}).get('trustee_user_id')

    @trustee_user_id.setter
    def trustee_user_id(self, value: str) -> None:
        if 'trust' not in self.root:
            self.root['trust'] = {}
        self.root['trust']['trustee_user_id'] = value

    @property
    def audit_id(self) -> str | None:
        try:
            return self._token.get('audit_ids', [])[0]
        except IndexError:
            return None

    @audit_id.setter
    def audit_id(self, value: str) -> None:
        audit_chain_id = self.audit_chain_id
        if audit_chain_id:
            lval = [value, audit_chain_id]
        else:
            lval = [value]
        self._token['audit_ids'] = lval

    @property
    def audit_chain_id(self) -> str | None:
        try:
            return self._token.get('audit_ids', [])[1]
        except IndexError:
            return None

    @audit_chain_id.setter
    def audit_chain_id(self, value: str) -> None:
        audit_id = self.audit_id
        if audit_id:
            self._token['audit_ids'] = [audit_id, value]
        else:
            self._token['audit_ids'] = [value]

    def validate(self) -> None:
        scoped = 'tenant' in self._token
        catalog = self.root.get('serviceCatalog')

        if catalog and not scoped:
            msg = 'You cannot have a service catalog on an unscoped token'
            raise exception.FixtureValidationError(msg)

        if scoped and not self._user.get('roles'):
            msg = 'You must have roles on a token to scope it'
            raise exception.FixtureValidationError(msg)

    def add_role(
        self, name: str | None = None, id: str | None = None
    ) -> dict[str, str]:
        role_id = id or uuid.uuid4().hex
        role_name = name or uuid.uuid4().hex

        if 'roles' not in self._user:
            self._user['roles'] = []
        self._user['roles'].append({'name': role_name})

        if 'roles' not in self._metadata:
            self._metadata['roles'] = []
        self._metadata['roles'].append(role_id)

        return {'id': role_id, 'name': role_name}

    def add_service(self, type: str, name: str | None = None) -> _Service:
        service_name = name or uuid.uuid4().hex
        service = _Service(name=service_name, type=type)

        if 'serviceCatalog' not in self.root:
            self.root['serviceCatalog'] = []
        self.root['serviceCatalog'].append(service)
        return service

    def remove_service(self, type: str) -> None:
        if 'serviceCatalog' in self.root:
            self.root['serviceCatalog'] = [
                f for f in self.root['serviceCatalog'] if f['type'] != type
            ]

    def set_scope(
        self, id: str | None = None, name: str | None = None
    ) -> None:
        self.tenant_id = id or uuid.uuid4().hex
        self.tenant_name = name or uuid.uuid4().hex

    def set_trust(
        self, id: str | None = None, trustee_user_id: str | None = None
    ) -> None:
        self.trust_id = id or uuid.uuid4().hex
        self.trustee_user_id = trustee_user_id or uuid.uuid4().hex

    def set_bind(self, name: str, data: ty.Any) -> None:
        if 'bind' not in self._token:
            self._token['bind'] = {}
        self._token['bind'][name] = data
