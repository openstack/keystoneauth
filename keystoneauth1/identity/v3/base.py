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
import json
import typing as ty
import warnings

import typing_extensions as ty_ext

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity import base
from keystoneauth1 import session as ks_session

_logger = utils.get_logger(__name__)

__all__ = ('Auth', 'AuthMethod', 'AuthConstructor', 'BaseAuth')


class BaseAuth(base.BaseIdentityPlugin, metaclass=abc.ABCMeta):
    """Identity V3 Authentication Plugin.

    :param string auth_url: Identity service endpoint for authentication.
    :param string trust_id: Trust ID for trust scoping.
    :param string system_scope: System information to scope to.
    :param string domain_id: Domain ID for domain scoping.
    :param string domain_name: Domain name for domain scoping.
    :param string project_id: Project ID for project scoping.
    :param string project_name: Project name for project scoping.
    :param string project_domain_id: Project's domain ID for project.
    :param string project_domain_name: Project's domain name for project.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True
    :param bool include_catalog: Include the service catalog in the returned
                                 token. (optional) default True.
    """

    auth_url: str

    def __init__(
        self,
        auth_url: str,
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
        super().__init__(auth_url=auth_url, reauthenticate=reauthenticate)

        self.trust_id = trust_id
        self.system_scope = system_scope
        self.domain_id = domain_id
        self.domain_name = domain_name
        self.project_id = project_id
        self.project_name = project_name
        self.project_domain_id = project_domain_id
        self.project_domain_name = project_domain_name
        self.include_catalog = include_catalog

    @property
    def token_url(self) -> str:
        """The full URL where we will send authentication data."""
        return '{}/auth/tokens'.format(self.auth_url.rstrip('/'))

    @property
    def has_scope_parameters(self) -> bool:
        """Return true if parameters can be used to create a scoped token."""
        return bool(
            self.domain_id
            or self.domain_name
            or self.project_id
            or self.project_name
            or self.trust_id
            or self.system_scope
        )


class _AuthIdentity(ty.TypedDict):
    identity: dict[str, ty.Any]
    scope: ty_ext.NotRequired[ty.Union[dict[str, ty.Any], str]]


class _AuthBody(ty.TypedDict):
    auth: _AuthIdentity


class Auth(BaseAuth):
    """Identity V3 Authentication Plugin.

    :param string auth_url: Identity service endpoint for authentication.
    :param list auth_methods: A collection of methods to authenticate with.
    :param string trust_id: Trust ID for trust scoping.
    :param string domain_id: Domain ID for domain scoping.
    :param string domain_name: Domain name for domain scoping.
    :param string project_id: Project ID for project scoping.
    :param string project_name: Project name for project scoping.
    :param string project_domain_id: Project's domain ID for project.
    :param string project_domain_name: Project's domain name for project.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True
    :param bool include_catalog: Include the service catalog in the returned
                                 token. (optional) default True.
    :param bool unscoped: Force the return of an unscoped token. This will make
                          the keystone server return an unscoped token even if
                          a default_project_id is set for this user.
    """

    def __init__(
        self,
        auth_url: str,
        auth_methods: list['AuthMethod'],
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
    ):
        super().__init__(
            auth_url=auth_url,
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
        self.unscoped = unscoped
        self.auth_methods = auth_methods

    def add_method(self, method: 'AuthMethod') -> None:
        """Add an additional initialized AuthMethod instance."""
        self.auth_methods.append(method)

    def get_auth_ref(self, session: ks_session.Session) -> access.AccessInfoV3:
        headers = {'Accept': 'application/json'}
        body: _AuthBody = {'auth': {'identity': {}}}
        ident = body['auth']['identity']
        # this is passed around for its side-effects
        rkwargs: dict[str, ty.Any] = {}

        for method in self.auth_methods:
            name, auth_data = method.get_auth_data(
                session, self, headers, request_kwargs=rkwargs
            )
            # NOTE(adriant): Methods like ReceiptMethod don't
            # want anything added to the request data, so they
            # explicitly return None, which we check for.
            if name:
                ident.setdefault('methods', []).append(name)
                ident[name] = auth_data

        if not ident:
            raise exceptions.AuthorizationFailure(
                'Authentication method required (e.g. password)'
            )

        mutual_exclusion = [
            bool(self.domain_id or self.domain_name),
            bool(self.project_id or self.project_name),
            bool(self.trust_id),
            bool(self.system_scope),
            bool(self.unscoped),
        ]

        if sum(mutual_exclusion) > 1:
            raise exceptions.AuthorizationFailure(
                message='Authentication cannot be scoped to multiple'
                ' targets. Pick one of: project, domain, '
                'trust, system or unscoped'
            )

        if self.domain_id:
            body['auth']['scope'] = {'domain': {'id': self.domain_id}}
        elif self.domain_name:
            body['auth']['scope'] = {'domain': {'name': self.domain_name}}
        elif self.project_id:
            body['auth']['scope'] = {'project': {'id': self.project_id}}
        elif self.project_name:
            scope = body['auth']['scope'] = {'project': {}}
            scope['project']['name'] = self.project_name

            if self.project_domain_id:
                scope['project']['domain'] = {'id': self.project_domain_id}
            elif self.project_domain_name:
                scope['project']['domain'] = {'name': self.project_domain_name}
        elif self.trust_id:
            body['auth']['scope'] = {'OS-TRUST:trust': {'id': self.trust_id}}
        elif self.unscoped:
            body['auth']['scope'] = 'unscoped'
        elif self.system_scope:
            # NOTE(lbragstad): Right now it's only possible to have role
            # assignments on the entire system. In the future that might change
            # so that users and groups can have roles on parts of the system,
            # like a specific service in a specific region. If that happens,
            # this will have to be accounted for here. Until then we'll only
            # support scoping to the entire system.
            if self.system_scope == 'all':
                body['auth']['scope'] = {'system': {'all': True}}

        token_url = self.token_url

        if not self.auth_url.rstrip('/').endswith('v3'):
            token_url = '{}/v3/auth/tokens'.format(self.auth_url.rstrip('/'))

        # NOTE(jamielennox): we add nocatalog here rather than in token_url
        # directly as some federation plugins require the base token_url
        if not self.include_catalog:
            token_url += '?nocatalog'

        _logger.debug('Making authentication request to %s', token_url)
        resp = session.post(
            token_url,
            json=body,
            headers=headers,
            authenticated=False,
            log=False,
            **rkwargs,
        )

        try:
            _logger.debug(json.dumps(resp.json()))
            resp_data = resp.json()
        except ValueError:
            raise exceptions.InvalidResponse(response=resp)

        if 'token' not in resp_data:
            raise exceptions.InvalidResponse(response=resp)

        return access.AccessInfoV3(
            auth_token=resp.headers['X-Subject-Token'], body=resp_data
        )

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        if not self.auth_methods:
            return {}

        params = {
            'auth_url': self.auth_url,
            'domain_id': self.domain_id,
            'domain_name': self.domain_name,
            'project_id': self.project_id,
            'project_name': self.project_name,
            'project_domain_id': self.project_domain_id,
            'project_domain_name': self.project_domain_name,
            'trust_id': self.trust_id,
        }

        for method in self.auth_methods:
            # may raise NotImplementedError but that's handled by
            # BaseIdentityPlugin.get_cache_id
            elements = method.get_cache_id_elements()
            params.update(elements)

        return params


class AuthMethod(metaclass=abc.ABCMeta):
    """One part of a V3 Authentication strategy.

    The v3 '/tokens' API allow multiple methods to be presented when
    authentication against the server. Each one of these methods is implemented
    by an AuthMethod.

    Note: When implementing an AuthMethod use keyword arguments to ensure they
    are supported by the MultiFactor auth plugin.
    """

    #: Deprecated parameter for defining the parameters supported by the
    #: plugin. These should now be defined by typed class attributes.
    _method_parameters: ty.Optional[list[str]] = None

    # TODO(stephenfin): Remove support for arbitrary arguments in 2025.2 or
    # later
    def __init__(self, **kwargs: object):
        if self._method_parameters is not None:
            warnings.warn(
                "Defining method parameter via '_method_parameters' is "
                "deprecated and will be removed in a future release. Migrate "
                "to typed class attributes and define an '__init__' method.",
                category=DeprecationWarning,
            )

            for param in self._method_parameters:
                setattr(self, param, kwargs.pop(param, None))

        if kwargs:
            msg = "Unexpected Attributes: {}".format(", ".join(kwargs.keys()))
            raise AttributeError(msg)

    @classmethod
    def _extract_kwargs(cls, kwargs: dict[str, object]) -> dict[str, object]:
        """Remove parameters related to this method from other kwargs."""
        _method_parameters = cls._method_parameters or []
        return {p: kwargs.pop(p, None) for p in _method_parameters}

    @abc.abstractmethod
    def get_auth_data(
        self,
        session: ks_session.Session,
        auth: Auth,
        headers: dict[str, str],
        request_kwargs: dict[str, object],
    ) -> ty.Union[tuple[None, None], tuple[str, ty.Mapping[str, object]]]:
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
        raise NotImplementedError()

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
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
        raise NotImplementedError()


@ty.runtime_checkable
class SupportsMultiFactor(ty.Protocol):
    _auth_method_class: ty.ClassVar[ty.Type[AuthMethod]]


class AuthConstructor(Auth, metaclass=abc.ABCMeta):
    """Abstract base class for creating an Auth Plugin.

    The Auth Plugin created contains only one authentication method. This
    is generally the required usage.

    An AuthConstructor creates an AuthMethod based on the method's
    arguments and the auth_method_class defined by the plugin. It then
    creates the auth plugin with only that authentication method.
    """

    _auth_method_class: ty.ClassVar[ty.Type[AuthMethod]]

    def __init__(
        self,
        auth_url: str,
        *args: ty.Any,
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
        **kwargs: ty.Any,
    ):
        warnings.warn(
            f"'{AuthConstructor.__qualname__}' is deprecated and will be "
            f"removed in a future release. Subclass '{Auth.__qualname__}' "
            f"instead and define typed class attributes and an '__init__' "
            f"method.",
            category=DeprecationWarning,
        )

        method_kwargs = self._auth_method_class._extract_kwargs(kwargs)
        # we should have consumed all "unknown" arguments by now
        assert kwargs == {}  # nosec B101
        method = self._auth_method_class(*args, **method_kwargs)
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
