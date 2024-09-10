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


"""Kerberos authentication plugins.

.. warning::
    This module requires installation of an extra package (`requests_kerberos`)
    not installed by default. Without the extra package an import error will
    occur. The extra package can be installed using::

      $ pip install keystoneauth1[kerberos]
"""

import typing as ty

try:
    # explicitly re-export symbol
    # https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
    import requests_kerberos as requests_kerberos
except ImportError:
    requests_kerberos = None

from keystoneauth1 import access
from keystoneauth1.identity import v3
from keystoneauth1.identity.v3 import federation
from keystoneauth1 import session as ks_session


# TODO(stephenfin): This should return an enum
def _mutual_auth(value: ty.Optional[str]) -> str:
    default = ty.cast(str, requests_kerberos.OPTIONAL)
    if value is None:
        return default
    return {
        'required': ty.cast(str, requests_kerberos.REQUIRED),
        'optional': ty.cast(str, requests_kerberos.OPTIONAL),
        'disabled': ty.cast(str, requests_kerberos.DISABLED),
    }.get(value.lower(), default)


def _requests_auth(
    mutual_authentication: ty.Optional[str],
) -> 'requests_kerberos.HTTPKerberosAuth':
    return requests_kerberos.HTTPKerberosAuth(
        mutual_authentication=_mutual_auth(mutual_authentication)
    )


def _dependency_check() -> None:
    if requests_kerberos is None:
        raise ImportError("""
Using the kerberos authentication plugin requires installation of additional
packages. These can be installed with::

    $ pip install keystoneauth1[kerberos]
""")


class KerberosMethod(v3.AuthMethod):
    mutual_auth: ty.Optional[str]

    def __init__(self, *, mutual_auth: ty.Optional[str] = None) -> None:
        self.mutual_auth = mutual_auth

        _dependency_check()

    def get_auth_data(
        self,
        session: ks_session.Session,
        auth: v3.Auth,
        headers: dict[str, str],
        request_kwargs: dict[str, object],
    ) -> ty.Union[tuple[None, None], tuple[str, ty.Mapping[str, object]]]:
        # NOTE(jamielennox): request_kwargs is passed as a kwarg however it is
        # required and always present when called from keystoneclient.
        request_kwargs['requests_auth'] = _requests_auth(self.mutual_auth)
        return 'kerberos', {}


class Kerberos(v3.Auth):
    _auth_method_class = KerberosMethod

    def __init__(
        self,
        auth_url: str,
        mutual_auth: ty.Optional[str] = None,
        *,
        unscoped: bool = False,
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
    ) -> None:
        method = self._auth_method_class(mutual_auth=mutual_auth)
        super().__init__(
            auth_url,
            [method],
            unscoped=unscoped,
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


class MappedKerberos(federation.FederationBaseAuth):
    """Authenticate using Kerberos via the keystone federation mechanisms.

    This uses the OS-FEDERATION extension to gain an unscoped token and then
    use the standard keystone auth process to scope that to any given project.
    """

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        mutual_auth: ty.Optional[str] = None,
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
    ) -> None:
        _dependency_check()
        self.mutual_auth = mutual_auth
        super().__init__(
            auth_url,
            identity_provider,
            protocol,
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

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        resp = session.get(
            self.federated_token_url,
            requests_auth=_requests_auth(self.mutual_auth),
            authenticated=False,
        )

        access_info = access.create(body=resp.json(), resp=resp)
        # narrow type
        assert isinstance(access_info, access.AccessInfoV3)  # nosec B101
        return access_info
