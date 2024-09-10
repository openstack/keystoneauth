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

try:
    # explicitly re-export symbol
    # https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
    from lxml import etree as etree
except ImportError:
    etree = None  # type: ignore[assignment]

from keystoneauth1 import exceptions
from keystoneauth1.identity import v3
from keystoneauth1 import session as ks_session


class _Saml2TokenAuthMethod(v3.AuthMethod):
    def __init__(self) -> None: ...

    def get_auth_data(
        self,
        session: ks_session.Session,
        auth: v3.Auth,
        headers: dict[str, str],
        request_kwargs: dict[str, object],
    ) -> ty.Union[tuple[None, None], tuple[str, ty.Mapping[str, object]]]:
        raise exceptions.HttpNotImplemented(
            'This method should never be called'
        )


_T = ty.TypeVar('_T')


class BaseSAMLPlugin(v3.FederationBaseAuth):
    HTTP_MOVED_TEMPORARILY = 302
    HTTP_SEE_OTHER = 303

    _auth_method_class = _Saml2TokenAuthMethod

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        identity_provider_url: str,
        username: str,
        password: str,
        protocol: str,
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
        """Class constructor accepting following parameters.

        :param auth_url: URL of the Identity Service
        :type auth_url: string

        :param identity_provider: Name of the Identity Provider the client
                                  will authenticate against. This parameter
                                  will be used to build a dynamic URL used to
                                  obtain unscoped OpenStack token.
        :type identity_provider: string

        :param identity_provider_url: An Identity Provider URL, where the
                                      SAML2 auhentication request will be
                                      sent.
        :type identity_provider_url: string

        :param username: User's login
        :type username: string

        :param password: User's password
        :type password: string

        :param protocol: Protocol to be used for the authentication.
                         The name must be equal to one configured at the
                         keystone sp side. This value is used for building
                         dynamic authentication URL.
                         Typical value would be: saml2
        :type protocol: string

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
        self.identity_provider_url = identity_provider_url
        self.username = username
        self.password = password

    @staticmethod
    def _first(_list: list[_T]) -> _T:
        if len(_list) != 1:
            raise IndexError('Only single element list is acceptable')
        return _list[0]

    @staticmethod
    def str_to_xml(
        content: bytes, msg: ty.Optional[str] = None, include_exc: bool = True
    ) -> etree._Element:
        try:
            return etree.XML(content)
        except etree.XMLSyntaxError as e:
            if not msg:
                msg = str(e)
            else:
                msg = msg % e if include_exc else msg
            raise exceptions.AuthorizationFailure(msg)

    @staticmethod
    def xml_to_str(content: etree._Element, **kwargs: ty.Any) -> bytes:
        return ty.cast(bytes, etree.tostring(content, **kwargs))
