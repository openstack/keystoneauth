# Copyright 2016 Spanish National Research Council
# Copyright 2016 INDIGO-DataCloud
# Copyright 2026 Rackspace Technology, Inc.
#
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

"""Keystone WebSSO authentication plugin.

Keystone's WebSSO endpoint delegates authentication to a browser. This plugin
opens the endpoint in the user's browser, listens on a loopback port for the
form POST that Keystone makes once the identity provider has authenticated the
user, and turns the token in that POST into an unscoped ``AccessInfo``.

The unscoped token it obtains can be rescoped to any project, domain or
system, so an application that holds on to it through
``get_unscoped_auth_state`` spares the user a login for each one.

WebSSO is not a standardised protocol. Keystone defined it so that Horizon
could authenticate users against an external identity provider, and modelled
it on the SAML 2.0 Web Browser SSO Profile: as in that profile's HTTP POST
binding, the identity service returns an auto-submitting HTML form which posts
the credential to a pre-registered, trusted origin. Because Keystone compares
that origin against its ``[federation] trusted_dashboard`` list verbatim, the
callback path and default port used here are the ones given in the Horizon and
Keystone federation installation guides rather than values of our choosing.

.. warning::

   The callback is open to login CSRF and cannot be closed to it. While the
   listener is running, any page open in the user's browser can submit a form
   to the callback port and have its own Keystone token accepted, which would
   leave the user operating as whoever obtained that token.

   Nothing in the request distinguishes such a submission from Keystone's. The
   Fetch Metadata headers of a scripted cross-origin form submission are
   identical to those of Keystone's auto-submitted form, and on the https to
   http callback that this flow relies on the Fetch standard serializes
   ``Origin`` as ``null`` and drops ``Referer`` for both.

   Binding the callback to the request it belongs to would need a nonce in the
   ``origin`` parameter, and there is nowhere to put one: Keystone requires
   that parameter to match a ``trusted_dashboard`` entry exactly, so it cannot
   carry per-request data. The window is limited instead: the listener binds to
   loopback only, runs only while a login is in progress, stops at the first
   token it accepts, and times out.
"""

import collections.abc
import ipaddress
import socket
import time
import typing as ty
import urllib.parse
import webbrowser
import wsgiref.simple_server
import wsgiref.types

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import federation
from keystoneauth1 import session as ks_session

_logger = utils.get_logger(__name__)

__all__ = ('WebSSO',)

# Keystone renders a form that POSTs the token to the ``origin`` URL, and
# ``origin`` has to match an entry in the server's ``[federation]
# trusted_dashboard`` list verbatim. Neither the path nor the query string can
# therefore vary between deployments.
_CALLBACK_PATH = '/auth/websso/'

_DEFAULT_REDIRECT_HOST = 'localhost'
_DEFAULT_REDIRECT_PORT = 9990

# How long to wait for the user to complete authentication in their browser.
_DEFAULT_TIMEOUT = 60

# The body only ever carries a single Keystone token, so anything remotely
# large is not something we sent the user to fetch.
_MAX_CALLBACK_BODY = 64 * 1024

_FORM_MEDIA_TYPE = 'application/x-www-form-urlencoded'

_SUCCESS_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Authentication complete</title>
    <script>window.close()</script>
  </head>
  <body>
    <p>Authentication is complete. You can close this window.</p>
  </body>
</html>
"""

_FAILURE_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Authentication failed</title>
  </head>
  <body>
    <p>This request was rejected. You can close this window.</p>
  </body>
</html>
"""


class _MissingTokenError(exceptions.AuthPluginException):
    """Keystone never delivered a token to the callback listener."""

    message = "Could not get a token from the WebSSO callback."


def _origin(url: str) -> str:
    """Reduce a URL to its scheme and authority, lowercased."""
    parsed = urllib.parse.urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'.lower()


def _assert_loopback(host: str) -> None:
    """Check that ``host`` only resolves to loopback addresses.

    The callback receives an unscoped Keystone token in a plain HTTP request,
    so the listener must not be reachable from another machine.
    """
    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise exceptions.OptionError(
            f'Could not resolve the redirect host {host!r}.'
        )

    for info in addresses:
        # Strip any IPv6 zone index before parsing.
        address = str(info[4][0]).partition('%')[0]
        if not ipaddress.ip_address(address).is_loopback:
            raise exceptions.OptionError(
                f'The redirect host {host!r} resolves to the non-loopback '
                f'address {address}. The WebSSO callback receives an '
                f'unscoped token and must not be exposed on a network '
                f'interface.'
            )


class _CallbackApp:
    """WSGI application that receives Keystone's WebSSO form POST.

    Accepts exactly one well formed POST and records the token from it. The
    listener is bound to a port that any page in the user's browser can post
    to, and nothing in the request proves it came from Keystone, so see the
    note on login CSRF in the module docstring.
    """

    def __init__(self, keystone_origin: str):
        self.token: str | None = None
        self._keystone_origin = keystone_origin

    def __call__(
        self,
        environ: wsgiref.types.WSGIEnvironment,
        start_response: wsgiref.types.StartResponse,
    ) -> list[bytes]:
        status, page = self._handle(environ)
        body = page.encode('utf-8')
        start_response(
            status,
            [
                ('Content-Type', 'text/html; charset=utf-8'),
                ('Content-Length', str(len(body))),
            ],
        )
        return [body]

    def _handle(
        self, environ: wsgiref.types.WSGIEnvironment
    ) -> tuple[str, str]:
        if environ.get('PATH_INFO') != _CALLBACK_PATH:
            return '404 Not Found', _FAILURE_HTML

        if environ.get('REQUEST_METHOD') != 'POST':
            return '405 Method Not Allowed', _FAILURE_HTML

        content_type = str(environ.get('CONTENT_TYPE', ''))
        if content_type.split(';')[0].strip().lower() != _FORM_MEDIA_TYPE:
            return '415 Unsupported Media Type', _FAILURE_HTML

        try:
            length = int(str(environ.get('CONTENT_LENGTH', '')))
        except ValueError:
            return '411 Length Required', _FAILURE_HTML

        if length < 0:
            return '411 Length Required', _FAILURE_HTML

        if length > _MAX_CALLBACK_BODY:
            return '413 Content Too Large', _FAILURE_HTML

        rejection = self._check_request_shape(environ)
        if rejection is not None:
            return rejection

        body = environ['wsgi.input'].read(length)
        fields = urllib.parse.parse_qs(body.decode('utf-8', 'replace'))
        token = next(iter(fields.get('token', [])), '')
        if not token:
            return '400 Bad Request', _FAILURE_HTML

        if self.token is not None:
            return '409 Conflict', _FAILURE_HTML

        self.token = token
        return '200 OK', _SUCCESS_HTML

    def _check_request_shape(
        self, environ: wsgiref.types.WSGIEnvironment
    ) -> tuple[str, str] | None:
        """Reject requests that do not look like Keystone's callback.

        These checks narrow what reaches the token handling below. None of
        them identify the sender: a page can submit a form to this port and
        produce the same request shape Keystone does. See the note on login
        CSRF in the module docstring.
        """
        # Keystone's callback template auto-submits a form, so its POST always
        # arrives as a top-level document navigation. Requiring that rejects
        # fetch() and XMLHttpRequest, which would otherwise reach us because a
        # form content type makes them "simple" cross-origin requests that need
        # no preflight.
        if environ.get('HTTP_SEC_FETCH_MODE') != 'navigate':
            _logger.debug('Rejected callback: not a navigation request')
            return '400 Bad Request', _FAILURE_HTML

        if environ.get('HTTP_SEC_FETCH_DEST') != 'document':
            _logger.debug('Rejected callback: not a document request')
            return '400 Bad Request', _FAILURE_HTML

        # 'none' means the user navigated here directly, which Keystone's
        # cross-site form post never does.
        if environ.get('HTTP_SEC_FETCH_SITE') == 'none':
            _logger.debug('Rejected callback: not a cross-site request')
            return '400 Bad Request', _FAILURE_HTML

        # A cross-origin POST navigation carries an Origin, but per the Fetch
        # standard it is serialized as 'null' when the referrer policy would
        # strip the referrer, which includes the https to http downgrade this
        # callback relies on. So a genuine POST from an HTTPS Keystone gives us
        # 'null' and we have to accept it. A real origin that is not Keystone's
        # cannot be genuine, though, so reject that.
        origin = environ.get('HTTP_ORIGIN')
        if origin not in (None, 'null') and (
            _origin(str(origin)) != self._keystone_origin
        ):
            _logger.debug('Rejected callback: unexpected origin')
            return '400 Bad Request', _FAILURE_HTML

        # The Referer is stripped outright on that same downgrade, so it is
        # normally absent. Check it only when the browser sends one.
        referer = environ.get('HTTP_REFERER')
        if referer and _origin(str(referer)) != self._keystone_origin:
            _logger.debug('Rejected callback: unexpected referer')
            return '400 Bad Request', _FAILURE_HTML

        return None


class _QuietWSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    """Request handler that keeps its access log off stderr."""

    def log_message(self, format: str, *args: ty.Any) -> None:
        """Do not log requests to stderr."""


def _wait_for_token(
    redirect_host: str,
    redirect_port: int,
    keystone_origin: str,
    start_flow: collections.abc.Callable[[], None],
    timeout: float = _DEFAULT_TIMEOUT,
) -> str:
    """Serve the callback endpoint until Keystone posts a token to it.

    ``start_flow`` is called once the callback port is listening, and is what
    sends the user into the flow.
    """
    _assert_loopback(redirect_host)

    app = _CallbackApp(keystone_origin)
    try:
        httpd = wsgiref.simple_server.make_server(
            redirect_host,
            redirect_port,
            app,
            handler_class=_QuietWSGIRequestHandler,
        )
    except OSError:
        _logger.error(
            'Cannot spawn the callback server on port %s, please specify a '
            'different port.',
            redirect_port,
        )
        raise

    with httpd:
        # Start the flow only now that the socket is bound and listening.
        # Keystone posts the token back as soon as the identity provider is
        # done, which with an established session can be before this function
        # would otherwise have got as far as accepting connections. There is
        # only one callback, so losing it means losing the login.
        start_flow()

        # handle_request() returns after any single request, including the ones
        # we reject, so keep serving until a token turns up or time runs out.
        deadline = time.monotonic() + timeout
        while app.token is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            httpd.timeout = remaining
            httpd.handle_request()

    if not app.token:
        raise _MissingTokenError()

    return app.token


class WebSSO(federation.FederationBaseAuth):
    """Authenticate using Keystone's browser based WebSSO flow.

    The user is sent to Keystone's WebSSO endpoint in their browser and
    authenticates there against the configured identity provider. Keystone
    then posts the resulting unscoped token back to a listener this plugin
    runs on a loopback port.

    The callback URL, ``http://<redirect_host>:<redirect_port>/auth/websso/``,
    must appear verbatim in the server's ``[federation] trusted_dashboard``
    list or Keystone refuses to complete the flow.

    ``username`` is optional and plays no part in authenticating: the identity
    is chosen in the browser. It only labels the unscoped token for caching, so
    a caller who signs in as more than one SSO account against the same
    identity provider can tell those accounts' cached tokens apart. Give each
    account a distinct value; leave it unset if there is only one.

    ``login_timeout`` is how many seconds to wait for the user to finish
    authenticating in the browser before giving up. The default suits an
    established session, but a first login through an external identity
    provider, particularly one that prompts for MFA, can take longer; raise it
    for those.
    """

    interactive_unscoped_auth = True

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        *,
        redirect_host: str = _DEFAULT_REDIRECT_HOST,
        redirect_port: int = _DEFAULT_REDIRECT_PORT,
        login_timeout: float = _DEFAULT_TIMEOUT,
        username: str | None = None,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
    ):
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
        self.redirect_host = redirect_host
        self.redirect_port = int(redirect_port)
        self.redirect_uri = (
            f'http://{self.redirect_host}:{self.redirect_port}{_CALLBACK_PATH}'
        )
        self.login_timeout = float(login_timeout)
        self.username = username

    def get_unscoped_cache_id_elements(self) -> dict[str, str | None]:
        """Add the caller supplied username to the unscoped token's identity.

        The browser, not this plugin, chooses who logs in, so the username is
        not used to authenticate and nothing checks it against the token that
        comes back. It is here only so a caller who authenticates as more than
        one SSO account against the same identity provider can keep their
        unscoped tokens apart in a cache; leaving it unset keeps the identifier
        as it would otherwise be.
        """
        elements = super().get_unscoped_cache_id_elements()
        elements['username'] = self.username
        return elements

    @property
    def _base_url(self) -> str:
        """The versioned root of the identity service."""
        host = self.auth_url.rstrip('/')
        if not host.endswith('v3'):
            host += '/v3'
        return host

    @property
    def federated_token_url(self) -> str:
        """URL that starts the WebSSO flow."""
        return (
            f'{self._base_url}/auth/OS-FEDERATION/identity_providers/'
            f'{self.identity_provider}/protocols/{self.protocol}/websso'
        )

    def _get_auth_token(self) -> str:
        """Send the user to their browser and wait for the token."""
        query = urllib.parse.urlencode({'origin': self.redirect_uri})
        url = f'{self.federated_token_url}?{query}'

        def open_browser() -> None:
            # Always show the URL. webbrowser.open() reports success whenever
            # it finds something to launch, which is not the same as the user
            # ending up on the page: xdg-open can exit zero having done
            # nothing, and over a remote shell the browser it picks may not be
            # one the user can see. This goes to the log, and so to standard
            # error, rather than standard output, where it would corrupt
            # machine readable output.
            _logger.warning('To authenticate please go to: %s', url)

            if not webbrowser.open(url, new=0):
                _logger.warning('A browser could not be opened for you.')

        return _wait_for_token(
            self.redirect_host,
            self.redirect_port,
            _origin(self.auth_url),
            open_browser,
            timeout=self.login_timeout,
        )

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Authenticate in a browser and return the unscoped token.

        Keystone hands back only the token itself, so it is validated against
        the identity service to pick up its expiry and catalog.
        """
        auth_token = self._get_auth_token()

        response = session.get(
            f'{self._base_url}/auth/tokens',
            headers={
                'X-Auth-Token': auth_token,
                'X-Subject-Token': auth_token,
            },
            authenticated=False,
        )
        auth_ref = access.create(body=response.json(), auth_token=auth_token)
        if not isinstance(auth_ref, access.AccessInfoV3):
            raise exceptions.InvalidResponse(response=response)

        return auth_ref
