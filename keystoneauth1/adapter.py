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

import argparse
import collections
import logging
import os
import typing as ty
import warnings

import requests

from keystoneauth1 import _fair_semaphore
from keystoneauth1 import discover
from keystoneauth1 import session

if ty.TYPE_CHECKING:
    from keystoneauth1 import plugin


class _BaseAdapter:
    """An instance of a session with local variables.

    A session is a global object that is shared around amongst many clients. It
    therefore contains state that is relevant to everyone. There is a lot of
    state such as the service type and region_name that are only relevant to a
    particular client that is using the session. An adapter provides a wrapper
    of client local data around the global session object.

    version, min_version, max_version and default_microversion can all be
    given either as a string or a tuple.

    :param session: The session object to wrap.
    :type session: keystoneauth1.session.Session
    :param str service_type: The default service_type for URL discovery.
    :param str service_name: The default service_name for URL discovery.
    :param str interface: The default interface for URL discovery.
    :param str region_name: The default region_name for URL discovery.
    :param str endpoint_override:
        Always use this endpoint URL for requests for this client.
    :param version:
        The minimum version restricted to a given Major API.
        Mutually exclusive with min_version and max_version.
        (optional)
    :param auth: An auth plugin to use instead of the session one.
    :type auth: keystoneauth1.plugin.BaseAuthPlugin
    :param str user_agent: The User-Agent string to set.
    :param int connect_retries:
        The maximum number of retries that should be attempted for
        connection errors. Default None - use session default which
        is don't retry.
    :param logger:
        A logging object to use for requests that pass through this
        adapter.
    :type logger: logging.Logger
    :param dict allow:
        Extra filters to pass when discovering API versions.  (optional)
    :param dict additional_headers:
        Additional headers that should be attached to every request
        passing through the adapter. Headers of the same name specified
        per request will take priority.
    :param str client_name:
        The name of the client that created the adapter. This will be
        used to create the user_agent.
    :param str client_version:
        The version of the client that created the adapter. This will
        be used to create the user_agent.
    :param bool allow_version_hack:
        Allow keystoneauth to hack up catalog URLS to support older schemes.
        (optional, default True)
    :param str global_request_id:
        A global_request_id (in the form of ``req-$uuid``) that will be
        passed on all requests. Enables cross project request id tracking.
    :param min_version:
        The minimum major version of a given API, intended to be used as
        the lower bound of a range with max_version. Mutually exclusive with
        version. If min_version is given with no max_version it is as
        if max version is 'latest'. (optional)
    :param max_version:
        The maximum major version of a given API, intended to be used as
        the upper bound of a range with min_version. Mutually exclusive with
        version. (optional)
    :param default_microversion:
        The default microversion value to send with API requests. While
        microversions are a per-request feature, a user may know they
        want to default to sending a specific value.  (optional)
    :param int status_code_retries:
        The maximum number of retries that should be attempted for retriable
        HTTP status codes (optional, defaults to 0 - never retry).
    :param list retriable_status_codes:
        List of HTTP status codes that should be retried (optional,
        defaults to HTTP 503, has no effect when status_code_retries is 0).
    :param bool raise_exc:
        If True, requests returning failing HTTP responses will raise an
        exception; if False, the response is returned. This can be
        overridden on a per-request basis via the kwarg of the same name.
    :param float rate_limit:
        A client-side rate limit to impose on requests made through this
        adapter in requests per second. For instance, a rate_limit of 2
        means to allow no more than 2 requests per second, and a rate_limit
        of 0.5 means to allow no more than 1 request every two seconds.
        (optional, defaults to None, which means no rate limiting will be
        applied).
    :param int concurrency:
        How many simultaneous http requests this Adapter can be used for.
        (optional, defaults to None, which means no limit).
    :param float connect_retry_delay:
        Delay (in seconds) between two connect retries (if enabled).
        By default exponential retry starting with 0.5 seconds up to
        a maximum of 60 seconds is used.
    :param float status_code_retry_delay:
        Delay (in seconds) between two status code retries (if enabled).
        By default exponential retry starting with 0.5 seconds up to
        a maximum of 60 seconds is used.
    """

    client_name: ty.Optional[str] = None
    client_version: ty.Optional[str] = None

    def __init__(
        self,
        session: session.Session,
        service_type: ty.Optional[str] = None,
        service_name: ty.Optional[str] = None,
        interface: ty.Optional[str] = None,
        region_name: ty.Optional[str] = None,
        endpoint_override: ty.Optional[str] = None,
        version: ty.Optional[str] = None,
        auth: ty.Optional['plugin.BaseAuthPlugin'] = None,
        user_agent: ty.Optional[str] = None,
        connect_retries: ty.Optional[int] = None,
        logger: ty.Optional[logging.Logger] = None,
        allow: ty.Optional[dict[str, ty.Any]] = None,
        additional_headers: ty.Optional[
            collections.abc.MutableMapping[str, str]
        ] = None,
        client_name: ty.Optional[str] = None,
        client_version: ty.Optional[str] = None,
        allow_version_hack: ty.Optional[bool] = None,
        global_request_id: ty.Optional[str] = None,
        min_version: ty.Optional[str] = None,
        max_version: ty.Optional[str] = None,
        default_microversion: ty.Optional[str] = None,
        status_code_retries: ty.Optional[int] = None,
        retriable_status_codes: ty.Optional[list[int]] = None,
        raise_exc: ty.Optional[bool] = None,
        rate_limit: ty.Optional[float] = None,
        concurrency: ty.Optional[int] = None,
        connect_retry_delay: ty.Optional[float] = None,
        status_code_retry_delay: ty.Optional[float] = None,
    ):
        if version and (min_version or max_version):
            raise TypeError(
                "version is mutually exclusive with min_version and"
                " max_version"
            )
        # NOTE(jamielennox): when adding new parameters to adapter please also
        # add them to the adapter call in httpclient.HTTPClient.__init__ as
        # well as to load_adapter_from_argparse below if the argument is
        # intended to be something a user would reasonably expect to set on
        # a command line
        self.session = session
        self.service_type = service_type
        self.service_name = service_name
        self.interface = interface
        self.region_name = region_name
        self.endpoint_override = endpoint_override
        self.version = version
        self.user_agent = user_agent
        self.auth = auth
        self.connect_retries = connect_retries
        self.logger = logger
        self.allow = allow or {}
        self.additional_headers = additional_headers or {}
        self.allow_version_hack = allow_version_hack
        self.min_version = min_version
        self.max_version = max_version
        self.default_microversion = default_microversion
        self.status_code_retries = status_code_retries
        self.retriable_status_codes = retriable_status_codes
        self.connect_retry_delay = connect_retry_delay
        self.status_code_retry_delay = status_code_retry_delay
        self.raise_exc = raise_exc

        self.global_request_id = global_request_id

        if client_name:
            self.client_name = client_name
        if client_version:
            self.client_version = client_version

        rate_delay = 0.0
        if rate_limit:
            # 1 / rate converts from requests per second to delay
            # between requests needed to achieve that rate.
            rate_delay = 1.0 / rate_limit

        self._rate_semaphore = _fair_semaphore.FairSemaphore(
            concurrency, rate_delay
        )

    def _set_endpoint_filter_kwargs(self, kwargs: dict[str, object]) -> None:
        if self.service_type:
            kwargs.setdefault('service_type', self.service_type)
        if self.service_name:
            kwargs.setdefault('service_name', self.service_name)
        if self.interface:
            kwargs.setdefault('interface', self.interface)
        if self.region_name:
            kwargs.setdefault('region_name', self.region_name)
        if self.version:
            kwargs.setdefault('version', self.version)
        if self.min_version:
            kwargs.setdefault('min_version', self.min_version)
        if self.max_version:
            kwargs.setdefault('max_version', self.max_version)
        if self.allow_version_hack is not None:
            kwargs.setdefault('allow_version_hack', self.allow_version_hack)

    def _request(
        self, url: str, method: str, **kwargs: ty.Any
    ) -> requests.Response:
        endpoint_filter = kwargs.setdefault('endpoint_filter', {})
        self._set_endpoint_filter_kwargs(endpoint_filter)
        # NOTE(gmann): Convert or initlize the headers to
        # CaseInsensitiveDict to make sure headers are
        # case insensitive.
        if kwargs.get('headers'):
            kwargs['headers'] = requests.structures.CaseInsensitiveDict(
                kwargs['headers']
            )
        else:
            kwargs['headers'] = requests.structures.CaseInsensitiveDict()
        if self.endpoint_override:
            kwargs.setdefault('endpoint_override', self.endpoint_override)

        if self.auth:
            kwargs.setdefault('auth', self.auth)
        if self.user_agent:
            kwargs.setdefault('user_agent', self.user_agent)
        for arg in (
            'connect_retries',
            'status_code_retries',
            'connect_retry_delay',
            'status_code_retry_delay',
            'retriable_status_codes',
        ):
            if getattr(self, arg) is not None:
                kwargs.setdefault(arg, getattr(self, arg))
        if self.logger:
            kwargs.setdefault('logger', self.logger)
        if self.allow:
            kwargs.setdefault('allow', self.allow)
        if self.default_microversion is not None:
            kwargs.setdefault('microversion', self.default_microversion)

        if isinstance(self.session, (session.Session, Adapter)):
            # these things are unsupported by keystoneclient's session so be
            # careful with them until everyone has transitioned to ksa.
            # Allowing adapter allows adapter nesting that auth_token does.
            if self.client_name:
                kwargs.setdefault('client_name', self.client_name)
            if self.client_version:
                kwargs.setdefault('client_version', self.client_version)
            if self._rate_semaphore:
                kwargs.setdefault('rate_semaphore', self._rate_semaphore)

        else:
            warnings.warn(
                'Using keystoneclient sessions has been deprecated. '
                'Please update your software to use keystoneauth1.'
            )

        for k, v in self.additional_headers.items():
            kwargs.setdefault('headers', {}).setdefault(k, v)

        if self.global_request_id is not None:
            kwargs.setdefault('headers', {}).setdefault(
                "X-OpenStack-Request-ID", self.global_request_id
            )

        if self.raise_exc is not None:
            kwargs.setdefault('raise_exc', self.raise_exc)

        return self.session.request(url, method, **kwargs)

    def get_token(
        self, auth: ty.Optional['plugin.BaseAuthPlugin'] = None
    ) -> ty.Optional[str]:
        """Return a token as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin
                     on the session. (optional)
        :type auth: keystoneauth1.plugin.BaseAuthPlugin

        :raises keystoneauth1.exceptions.auth.AuthorizationFailure: if a new
            token fetch fails.

        :returns: A valid token.
        :rtype: :class:`str`
        """
        return self.session.get_token(auth or self.auth)

    def get_endpoint(
        self,
        auth: ty.Optional['plugin.BaseAuthPlugin'] = None,
        **kwargs: ty.Any,
    ) -> ty.Optional[str]:
        """Get an endpoint as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin on
                     the session. (optional)
        :type auth: keystoneauth1.plugin.BaseAuthPlugin

        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin: if a
            plugin is not available.

        :returns: An endpoint if available or None.
        :rtype: :class:`str`
        """
        if self.endpoint_override:
            return self.endpoint_override

        self._set_endpoint_filter_kwargs(kwargs)
        return self.session.get_endpoint(auth or self.auth, **kwargs)

    def get_endpoint_data(
        self, auth: ty.Optional['plugin.BaseAuthPlugin'] = None
    ) -> ty.Optional['discover.EndpointData']:
        """Get the endpoint data for this Adapter's endpoint.

        :param auth: The auth plugin to use for token. Overrides the plugin on
                     the session. (optional)
        :type auth: keystoneauth1.plugin.BaseAuthPlugin

        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin: if a
            plugin is not available.
        :raises TypeError: If arguments are invalid

        :returns: Endpoint data if available or None.
        :rtype: keystoneauth1.discover.EndpointData
        """
        kwargs: dict[str, ty.Any] = {}
        self._set_endpoint_filter_kwargs(kwargs)
        if self.endpoint_override:
            kwargs['endpoint_override'] = self.endpoint_override

        return self.session.get_endpoint_data(auth or self.auth, **kwargs)

    def get_all_version_data(
        self, interface: str = 'public', region_name: ty.Optional[str] = None
    ) -> dict[str, dict[str, dict[str, list[discover.VersionData]]]]:
        """Get data about all versions of a service.

        :param interface:
            Type of endpoint to get version data for. Can be a single value
            or a list of values. A value of None indicates that all interfaces
            should be queried. (optional, defaults to public)
        :param string region_name:
            Region of endpoints to get version data for. A valueof None
            indicates that all regions should be queried. (optional, defaults
            to None)
        :returns: A dictionary keyed by region_name with values containing
            dictionaries keyed by interface with values being a list of
            :class:`~keystoneauth1.discover.VersionData`.
        """
        return self.session.get_all_version_data(
            interface=interface,
            region_name=region_name,
            service_type=self.service_type,
        )

    def get_api_major_version(
        self,
        auth: ty.Optional['plugin.BaseAuthPlugin'] = None,
        **kwargs: ty.Any,
    ) -> ty.Optional[tuple[ty.Union[int, float], ...]]:
        """Get the major API version as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin on
                     the session. (optional)
        :type auth: keystoneauth1.plugin.BaseAuthPlugin

        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin: if a
            plugin is not available.

        :return: The major version of the API of the service discovered.
        :rtype: tuple or None
        """
        self._set_endpoint_filter_kwargs(kwargs)
        if self.endpoint_override:
            kwargs['endpoint_override'] = self.endpoint_override

        return self.session.get_api_major_version(auth or self.auth, **kwargs)

    def invalidate(
        self, auth: ty.Optional['plugin.BaseAuthPlugin'] = None
    ) -> bool:
        """Invalidate an authentication plugin.

        :param auth: The auth plugin to invalidate. Overrides the plugin on the
                     session. (optional)
        :type auth: keystoneauth1.plugin.BaseAuthPlugin
        """
        return self.session.invalidate(auth or self.auth)

    def get_user_id(
        self, auth: ty.Optional['plugin.BaseAuthPlugin'] = None
    ) -> ty.Optional[str]:
        """Return the authenticated user_id as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin
                     on the session. (optional)
        :type auth: keystoneauth1.plugin.BaseAuthPlugin

        :raises keystoneauth1.exceptions.auth.AuthorizationFailure:
            if a new token fetch fails.
        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin:
            if a plugin is not available.

        :returns: Current `user_id` or None if not supported by plugin.
        :rtype: :class:`str`
        """
        return self.session.get_user_id(auth or self.auth)

    def get_project_id(
        self, auth: ty.Optional['plugin.BaseAuthPlugin'] = None
    ) -> ty.Optional[str]:
        """Return the authenticated project_id as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin
                     on the session. (optional)
        :type auth: keystoneauth1.plugin.BaseAuthPlugin

        :raises keystoneauth1.exceptions.auth.AuthorizationFailure:
            if a new token fetch fails.
        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin:
            if a plugin is not available.

        :returns: Current `project_id` or None if not supported by plugin.
        :rtype: :class:`str`
        """
        return self.session.get_project_id(auth or self.auth)

    # TODO(efried): Move this to loading.adapter.Adapter
    @classmethod
    def register_argparse_arguments(
        cls,
        parser: argparse.ArgumentParser,
        service_type: ty.Optional[str] = None,
    ) -> None:
        """Attach arguments to a given argparse Parser for Adapters.

        :param parser: The argparse parser to attach options to.
        :type parser: argparse.ArgumentParser
        :param str service_type: Default service_type value. (optional)
        """
        adapter_group = parser.add_argument_group(
            'Service Options',
            'Options controlling the specialization of the API '
            'Connection from information found in the catalog',
        )

        adapter_group.add_argument(
            '--os-service-type',
            metavar='<name>',
            default=os.environ.get('OS_SERVICE_TYPE', service_type),
            help='Service type to request from the catalog',
        )

        adapter_group.add_argument(
            '--os-service-name',
            metavar='<name>',
            default=os.environ.get('OS_SERVICE_NAME', None),
            help='Service name to request from the catalog',
        )

        adapter_group.add_argument(
            '--os-interface',
            metavar='<name>',
            default=os.environ.get('OS_INTERFACE', 'public'),
            help='API Interface to use [public, internal, admin]',
        )

        adapter_group.add_argument(
            '--os-region-name',
            metavar='<name>',
            default=os.environ.get('OS_REGION_NAME', None),
            help='Region of the cloud to use',
        )

        adapter_group.add_argument(
            '--os-endpoint-override',
            metavar='<name>',
            default=os.environ.get('OS_ENDPOINT_OVERRIDE', None),
            help='Endpoint to use instead of the endpoint in the catalog',
        )

        adapter_group.add_argument(
            '--os-api-version',
            metavar='<name>',
            default=os.environ.get('OS_API_VERSION', None),
            help='Which version of the service API to use',
        )

    # TODO(efried): Move this to loading.adapter.Adapter
    @classmethod
    def register_service_argparse_arguments(
        cls, parser: argparse.ArgumentParser, service_type: str
    ) -> None:
        """Attach arguments to a given argparse Parser for Adapters.

        :param parser: The argparse parser to attach options to.
        :type parser: argparse.ArgumentParser
        :param str service_type: Name of a service to generate additional
                                 arguments for.
        """
        service_env = service_type.upper().replace('-', '_')
        adapter_group = parser.add_argument_group(
            f'{service_type.title()} Service Options',
            f'Options controlling the specialization of the '
            f'{service_type.title()} API Connection from information found in '
            f'the catalog',
        )

        adapter_group.add_argument(
            f'--os-{service_type}-service-type',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_SERVICE_TYPE', None),
            help=(
                f'Service type to request from the catalog for the '
                f'{service_type} service'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-service-name',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_SERVICE_NAME', None),
            help=(
                f'Service name to request from the catalog for the '
                f'{service_type} service'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-interface',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_INTERFACE', None),
            help=(
                f'API Interface to use for the {service_type} service '
                f'[public, internal, admin]'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-api-version',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_API_VERSION', None),
            help=(
                f'Which version of the service API to use for '
                f'the {service_type} service'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-endpoint-override',
            metavar='<name>',
            default=os.environ.get(
                f'OS_{service_env}_ENDPOINT_OVERRIDE', None
            ),
            help=(
                f'Endpoint to use for the {service_type} service '
                f'instead of the endpoint in the catalog'
            ),
        )


class Adapter(_BaseAdapter):
    def request(
        self, url: str, method: str, **kwargs: ty.Any
    ) -> requests.Response:
        return self._request(url, method, **kwargs)

    def get(self, url: str, **kwargs: ty.Any) -> requests.Response:
        """Perform a GET request.

        This calls :py:meth:`.request()` with ``method`` set to ``GET``.
        """
        return self.request(url, 'GET', **kwargs)

    def head(self, url: str, **kwargs: ty.Any) -> requests.Response:
        """Perform a HEAD request.

        This calls :py:meth:`.request()` with ``method`` set to ``HEAD``.
        """
        return self.request(url, 'HEAD', **kwargs)

    def post(self, url: str, **kwargs: ty.Any) -> requests.Response:
        """Perform a POST request.

        This calls :py:meth:`.request()` with ``method`` set to ``POST``.
        """
        return self.request(url, 'POST', **kwargs)

    def put(self, url: str, **kwargs: ty.Any) -> requests.Response:
        """Perform a PUT request.

        This calls :py:meth:`.request()` with ``method`` set to ``PUT``.
        """
        return self.request(url, 'PUT', **kwargs)

    def patch(self, url: str, **kwargs: ty.Any) -> requests.Response:
        """Perform a PATCH request.

        This calls :py:meth:`.request()` with ``method`` set to ``PATCH``.
        """
        return self.request(url, 'PATCH', **kwargs)

    def delete(self, url: str, **kwargs: ty.Any) -> requests.Response:
        """Perform a DELETE request.

        This calls :py:meth:`.request()` with ``method`` set to ``DELETE``.
        """
        return self.request(url, 'DELETE', **kwargs)


class LegacyJsonAdapter(_BaseAdapter):
    """Make something that looks like an old HTTPClient.

    A common case when using an adapter is that we want an interface similar to
    the HTTPClients of old which returned the body as JSON as well.

    You probably don't want this if you are starting from scratch.
    """

    def request(
        self, url: str, method: str, **kwargs: ty.Any
    ) -> tuple[requests.Response, object]:
        headers = kwargs.setdefault('headers', {})
        headers.setdefault('Accept', 'application/json')

        try:
            kwargs['json'] = kwargs.pop('body')
        except KeyError:
            pass

        resp = self._request(url, method, **kwargs)

        try:
            body = resp.json()
        except ValueError:
            body = None

        return resp, body

    def get(
        self, url: str, **kwargs: ty.Any
    ) -> tuple[requests.Response, object]:
        """Perform a GET request.

        This calls :py:meth:`.request()` with ``method`` set to ``GET``.
        """
        return self.request(url, 'GET', **kwargs)

    def head(
        self, url: str, **kwargs: ty.Any
    ) -> tuple[requests.Response, object]:
        """Perform a HEAD request.

        This calls :py:meth:`.request()` with ``method`` set to ``HEAD``.
        """
        return self.request(url, 'HEAD', **kwargs)

    def post(
        self, url: str, **kwargs: ty.Any
    ) -> tuple[requests.Response, object]:
        """Perform a POST request.

        This calls :py:meth:`.request()` with ``method`` set to ``POST``.
        """
        return self.request(url, 'POST', **kwargs)

    def put(
        self, url: str, **kwargs: ty.Any
    ) -> tuple[requests.Response, object]:
        """Perform a PUT request.

        This calls :py:meth:`.request()` with ``method`` set to ``PUT``.
        """
        return self.request(url, 'PUT', **kwargs)

    def patch(
        self, url: str, **kwargs: ty.Any
    ) -> tuple[requests.Response, object]:
        """Perform a PATCH request.

        This calls :py:meth:`.request()` with ``method`` set to ``PATCH``.
        """
        return self.request(url, 'PATCH', **kwargs)

    def delete(
        self, url: str, **kwargs: ty.Any
    ) -> tuple[requests.Response, object]:
        """Perform a DELETE request.

        This calls :py:meth:`.request()` with ``method`` set to ``DELETE``.
        """
        return self.request(url, 'DELETE', **kwargs)


# TODO(efried): Deprecate this in favor of
#               loading.adapter.register_argparse_arguments
def register_adapter_argparse_arguments(
    parser: argparse.ArgumentParser, service_type: ty.Optional[str] = None
) -> None:
    return Adapter.register_argparse_arguments(
        parser=parser, service_type=service_type
    )


# TODO(efried): Deprecate this in favor of
#               loading.adapter.register_service_argparse_arguments
def register_service_adapter_argparse_arguments(
    parser: argparse.ArgumentParser, service_type: str
) -> None:
    return Adapter.register_service_argparse_arguments(
        parser=parser, service_type=service_type
    )
