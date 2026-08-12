# Copyright 2026 Rackspace Technology, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import copy
import datetime
import io
import socket
from unittest import mock
import urllib.parse
import uuid

import fixtures

from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import websso
from keystoneauth1 import session
from keystoneauth1.tests.unit import oidc_fixtures
from keystoneauth1.tests.unit import utils


KEYSTONE_TOKEN_VALUE = uuid.uuid4().hex
KEYSTONE_ORIGIN = 'https://keystone.example.org'


def _token_body(expires_in=3600):
    """Return an unscoped token body that expires ``expires_in`` from now."""
    body = copy.deepcopy(oidc_fixtures.UNSCOPED_TOKEN)
    expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
        seconds=expires_in
    )
    body['token']['expires_at'] = expires_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return body


def _wait_running_flow(token=KEYSTONE_TOKEN_VALUE):
    """Stand in for _wait_for_token that runs the flow callback it is given."""

    def wait(
        redirect_host,
        redirect_port,
        keystone_origin,
        start_flow,
        timeout=websso._DEFAULT_TIMEOUT,
    ):
        start_flow()
        return token

    return wait


class CallbackAppTests(utils.TestCase):
    """Exercise the loopback listener without going near a socket."""

    def _environ(self, drop=(), body=None, **overrides):
        if body is None:
            body = f'token={KEYSTONE_TOKEN_VALUE}'
        environ = {
            'PATH_INFO': '/auth/websso/',
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'CONTENT_LENGTH': str(len(body)),
            'HTTP_SEC_FETCH_MODE': 'navigate',
            'HTTP_SEC_FETCH_DEST': 'document',
            'HTTP_SEC_FETCH_SITE': 'cross-site',
            'wsgi.input': io.BytesIO(body.encode('utf-8')),
        }
        environ.update(overrides)
        for key in drop:
            environ.pop(key, None)
        return environ

    def _call(self, app=None, **kwargs):
        """Send one request, returning the status, body and headers."""
        app = app if app is not None else websso._CallbackApp(KEYSTONE_ORIGIN)
        started = []

        def start_response(status, headers):
            started.append((status, headers))

        body = b''.join(app(self._environ(**kwargs), start_response))
        status, headers = started[0]
        return app, status, body, dict(headers)

    def test_accepts_keystones_post(self):
        app, status, body, headers = self._call()

        self.assertEqual('200 OK', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, app.token)
        self.assertIn(b'<!doctype html>', body)
        self.assertEqual('text/html; charset=utf-8', headers['Content-Type'])

    def test_rejects_requests_keystone_would_not_send(self):
        rejections = [
            ('wrong path', {'PATH_INFO': '/'}, '404 Not Found'),
            (
                'wrong method',
                {'REQUEST_METHOD': 'GET'},
                '405 Method Not Allowed',
            ),
            (
                'wrong content type',
                {'CONTENT_TYPE': 'application/json'},
                '415 Unsupported Media Type',
            ),
            (
                'missing Content-Length',
                {'drop': ['CONTENT_LENGTH']},
                '411 Length Required',
            ),
            (
                'unparsable Content-Length',
                {'CONTENT_LENGTH': 'banana'},
                '411 Length Required',
            ),
            (
                'oversized body',
                {'CONTENT_LENGTH': str(websso._MAX_CALLBACK_BODY + 1)},
                '413 Content Too Large',
            ),
            # A cross-origin fetch() or XMLHttpRequest carrying a form content
            # type is a "simple" request and reaches us without a preflight.
            # Requiring a document navigation is what excludes it.
            (
                'scripted fetch',
                {
                    'HTTP_SEC_FETCH_MODE': 'no-cors',
                    'HTTP_SEC_FETCH_DEST': 'empty',
                },
                '400 Bad Request',
            ),
            (
                'missing Sec-Fetch-Mode',
                {'drop': ['HTTP_SEC_FETCH_MODE']},
                '400 Bad Request',
            ),
            (
                'missing Sec-Fetch-Dest',
                {'drop': ['HTTP_SEC_FETCH_DEST']},
                '400 Bad Request',
            ),
            (
                'subresource rather than document',
                {'HTTP_SEC_FETCH_DEST': 'iframe'},
                '400 Bad Request',
            ),
            # 'none' means the user pasted the URL into the address bar.
            (
                'address bar navigation',
                {'HTTP_SEC_FETCH_SITE': 'none'},
                '400 Bad Request',
            ),
            (
                'foreign Origin',
                {'HTTP_ORIGIN': 'http://evil.example.net'},
                '400 Bad Request',
            ),
            (
                'foreign Referer',
                {'HTTP_REFERER': 'https://evil.example.net/x'},
                '400 Bad Request',
            ),
            ('no token field', {'body': 'notatoken=1'}, '400 Bad Request'),
            ('empty token field', {'body': 'token='}, '400 Bad Request'),
        ]

        for description, request, expected in rejections:
            with self.subTest(description):
                app, status, _, _ = self._call(**request)

                self.assertEqual(expected, status)
                self.assertIsNone(app.token)

    def test_accepts_the_variations_keystone_can_send(self):
        accepted = [
            (
                'content type with charset',
                {
                    'CONTENT_TYPE': (
                        'application/x-www-form-urlencoded; charset=utf-8'
                    )
                },
            ),
            ('no Sec-Fetch-Site', {'drop': ['HTTP_SEC_FETCH_SITE']}),
            ("Keystone's Origin", {'HTTP_ORIGIN': KEYSTONE_ORIGIN}),
            # The Fetch standard serializes Origin as 'null', and the default
            # referrer policy drops Referer, when the request downgrades from
            # https to http. That is the documented callback, so a genuine POST
            # normally arrives with both missing or uninformative.
            ('Origin: null from the downgrade', {'HTTP_ORIGIN': 'null'}),
            ('no Origin', {'drop': ['HTTP_ORIGIN']}),
            (
                "Keystone's Referer",
                {'HTTP_REFERER': f'{KEYSTONE_ORIGIN}/v3/auth/OS-FEDERATION'},
            ),
            ('no Referer', {}),
        ]

        for description, request in accepted:
            with self.subTest(description):
                app, status, _, _ = self._call(**request)

                self.assertEqual('200 OK', status)
                self.assertEqual(KEYSTONE_TOKEN_VALUE, app.token)

    def test_scripted_cross_origin_form_post_is_not_rejected(self):
        # Documents the known login CSRF exposure: a form submitted by another
        # page produces the same request as Keystone's auto-submitted form. If
        # this ever starts failing, a real binding mechanism has been found and
        # the warnings in the docs should be revisited.
        app, status, _, _ = self._call(
            HTTP_ORIGIN='null', body='token=attacker-token'
        )

        self.assertEqual('200 OK', status)
        self.assertEqual('attacker-token', app.token)

    def test_only_the_first_token_is_accepted(self):
        app, status, _, _ = self._call()
        self.assertEqual('200 OK', status)

        _, status, _, _ = self._call(app=app, body=f'token={uuid.uuid4().hex}')

        self.assertEqual('409 Conflict', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, app.token)

    def test_a_rejected_post_does_not_prevent_a_later_good_one(self):
        app, status, _, _ = self._call(REQUEST_METHOD='GET')
        self.assertEqual('405 Method Not Allowed', status)
        self.assertIsNone(app.token)

        _, status, _, _ = self._call(app=app)

        self.assertEqual('200 OK', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, app.token)


class LoopbackTests(utils.TestCase):
    def test_loopback_hosts_are_allowed(self):
        for host in ('localhost', '127.0.0.1'):
            with self.subTest(host):
                websso._assert_loopback(host)

    def test_non_loopback_is_rejected(self):
        with mock.patch.object(socket, 'getaddrinfo') as m:
            m.return_value = [
                (socket.AF_INET, None, None, '', ('192.0.2.10', 0))
            ]
            e = self.assertRaises(
                exceptions.OptionError,
                websso._assert_loopback,
                'somewhere.example.org',
            )

        self.assertIn('non-loopback', str(e))

    def test_unresolvable_is_rejected(self):
        with mock.patch.object(socket, 'getaddrinfo') as m:
            m.side_effect = socket.gaierror
            self.assertRaises(
                exceptions.OptionError, websso._assert_loopback, 'nope.invalid'
            )


class WaitForTokenTests(utils.TestCase):
    def _noop(self):
        pass

    def test_returns_the_token_once_posted(self):
        with mock.patch.object(
            websso.wsgiref.simple_server, 'make_server'
        ) as m:

            def handle_request():
                # Whatever the app records is what we should get back.
                m.call_args[0][2].token = KEYSTONE_TOKEN_VALUE

            m.return_value.__enter__.return_value = m.return_value
            m.return_value.handle_request.side_effect = handle_request

            token = websso._wait_for_token(
                'localhost', 9990, KEYSTONE_ORIGIN, self._noop
            )

        self.assertEqual(KEYSTONE_TOKEN_VALUE, token)

    def test_callback_port_is_listening_before_the_flow_starts(self):
        # An identity provider with an established session posts the token
        # back as soon as the flow starts. Connecting from inside start_flow
        # pins the ordering: if the socket were not bound until afterwards,
        # this connect would be refused and the single callback lost.
        body = f'token={KEYSTONE_TOKEN_VALUE}'.encode()
        request = (
            b'POST /auth/websso/ HTTP/1.1\r\n'
            b'Host: localhost\r\n'
            b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
            b'Sec-Fetch-Mode: navigate\r\n'
            b'Sec-Fetch-Dest: document\r\n'
            b'Sec-Fetch-Site: cross-site\r\n'
            b'Connection: close\r\n'
            b'\r\n' + body
        )
        connections = []

        def start_flow():
            # Not wrapped in assertRaises: a refused connection here fails the
            # test with ConnectionRefusedError, which is the point.
            conn = socket.create_connection(('127.0.0.1', port), timeout=10)
            connections.append(conn)
            conn.sendall(request)

        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]

        token = websso._wait_for_token(
            'localhost', port, KEYSTONE_ORIGIN, start_flow, timeout=10
        )

        self.addCleanup(connections[0].close)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, token)
        # The response only arrives once the serving loop has run, so reading
        # it here also confirms the request was accepted rather than rejected.
        self.assertIn(b'200 OK', connections[0].recv(4096))

    def test_an_unavailable_port_fails_before_the_flow_starts(self):
        started = []
        with socket.socket() as taken:
            taken.bind(('127.0.0.1', 0))
            taken.listen(1)
            port = taken.getsockname()[1]

            self.assertRaises(
                OSError,
                websso._wait_for_token,
                'localhost',
                port,
                KEYSTONE_ORIGIN,
                lambda: started.append(True),
            )

        self.assertEqual([], started)

    def test_timeout_raises(self):
        with mock.patch.object(
            websso.wsgiref.simple_server, 'make_server'
        ) as m:
            m.return_value.__enter__.return_value = m.return_value

            self.assertRaises(
                websso._MissingTokenError,
                websso._wait_for_token,
                'localhost',
                9990,
                KEYSTONE_ORIGIN,
                self._noop,
                timeout=0,
            )

        m.return_value.handle_request.assert_not_called()


class WebSSOTests(utils.TestCase):
    def setUp(self):
        super().setUp()

        self.session = session.Session()
        self.AUTH_URL = 'http://keystone/v3'
        self.IDENTITY_PROVIDER = 'bluepages'
        self.PROTOCOL = 'openid'

    def _plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.AUTH_URL)
        kwargs.setdefault('identity_provider', self.IDENTITY_PROVIDER)
        kwargs.setdefault('protocol', self.PROTOCOL)
        return websso.WebSSO(**kwargs)

    def _stub_token_validation(self, body=None):
        return self.requests_mock.get(
            f'{self.AUTH_URL}/auth/tokens',
            json=body if body is not None else _token_body(),
            headers={'X-Subject-Token': KEYSTONE_TOKEN_VALUE},
        )

    def _mock_flow(self, mock_open, mock_wait, opens=True, token=None):
        mock_open.return_value = opens
        mock_wait.side_effect = _wait_running_flow(
            token if token is not None else KEYSTONE_TOKEN_VALUE
        )

    # -- URL construction ---------------------------------------------------

    def test_federated_token_url(self):
        expected = (
            f'{self.AUTH_URL}/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso'
        )

        for auth_url in (
            'http://keystone/v3',
            'http://keystone/v3/',
            'http://keystone',
        ):
            with self.subTest(auth_url):
                plugin = self._plugin(auth_url=auth_url)

                self.assertEqual(expected, plugin.federated_token_url)

    def test_redirect_uri(self):
        cases = [
            ({}, 'http://localhost:9990/auth/websso/'),
            (
                {'redirect_host': '127.0.0.1', 'redirect_port': 9991},
                'http://127.0.0.1:9991/auth/websso/',
            ),
        ]

        for kwargs, expected in cases:
            with self.subTest(expected):
                self.assertEqual(expected, self._plugin(**kwargs).redirect_uri)

    # -- unscoped cache id --------------------------------------------------

    def test_username_partitions_the_unscoped_cache_id(self):
        base_id = self._plugin().get_unscoped_cache_id()
        self.assertIsNotNone(base_id)

        # Leaving username unset keeps the identifier as it would be without
        # the field at all.
        self.assertEqual(
            base_id, self._plugin(username=None).get_unscoped_cache_id()
        )

        # Different SSO accounts get different identifiers, and each differs
        # from the unlabelled one.
        alice = self._plugin(username='alice').get_unscoped_cache_id()
        bob = self._plugin(username='bob').get_unscoped_cache_id()
        self.assertNotEqual(base_id, alice)
        self.assertNotEqual(base_id, bob)
        self.assertNotEqual(alice, bob)

    def test_username_does_not_affect_the_flow_urls(self):
        # The username only labels the cache; it must not leak into the
        # request the user is sent through in the browser.
        plain = self._plugin()
        labelled = self._plugin(username='alice')

        self.assertEqual(
            plain.federated_token_url, labelled.federated_token_url
        )
        self.assertEqual(plain.redirect_uri, labelled.redirect_uri)

    # -- browser handoff ----------------------------------------------------

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_browser_is_opened_with_encoded_origin(self, mock_open, mock_wait):
        self._mock_flow(mock_open, mock_wait)
        plugin = self._plugin()

        self.assertEqual(KEYSTONE_TOKEN_VALUE, plugin._get_auth_token())

        url = mock_open.call_args[0][0]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual([plugin.redirect_uri], query['origin'])
        self.assertTrue(url.startswith(plugin.federated_token_url))
        # The Referer, when present, is Keystone's origin rather than ours.
        self.assertEqual(
            ('localhost', 9990, 'http://keystone'), mock_wait.call_args[0][:3]
        )

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_login_timeout_is_passed_through(self, mock_open, mock_wait):
        self._mock_flow(mock_open, mock_wait)

        with self.subTest('default'):
            self._plugin()._get_auth_token()
            self.assertEqual(60.0, mock_wait.call_args.kwargs['timeout'])

        with self.subTest('overridden'):
            self._plugin(login_timeout=300)._get_auth_token()
            self.assertEqual(300.0, mock_wait.call_args.kwargs['timeout'])

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_url_is_always_logged(self, mock_open, mock_wait):
        # A successful return from webbrowser.open() does not mean the user
        # ended up on the page, so the URL has to be shown either way.
        for opens in (True, False):
            with self.subTest(f'webbrowser.open() -> {opens}'):
                self._mock_flow(mock_open, mock_wait, opens=opens)
                plugin = self._plugin()

                plugin._get_auth_token()

                self.assertIn(
                    'To authenticate please go to', self.logger.output
                )
                self.assertIn(plugin.federated_token_url, self.logger.output)
                self.assertEqual(
                    not opens, 'could not be opened' in self.logger.output
                )

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_nothing_user_facing_goes_to_stdout(self, mock_open, mock_wait):
        # stdout is where consumers put machine readable output, so the URL
        # must not be written there.
        self._mock_flow(mock_open, mock_wait, opens=False)
        stdout = self.useFixture(fixtures.StringStream('stdout'))

        with mock.patch('sys.stdout', stdout.stream):
            self._plugin()._get_auth_token()

        self.assertEqual('', stdout.getDetails()['stdout'].as_text())

    # -- end to end ---------------------------------------------------------

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_get_unscoped_auth_ref(self, mock_open, mock_wait):
        self._mock_flow(mock_open, mock_wait)
        self._stub_token_validation()

        auth_ref = self._plugin().get_unscoped_auth_ref(self.session)

        self.assertEqual(KEYSTONE_TOKEN_VALUE, auth_ref.auth_token)
        self.assertRequestHeaderEqual('X-Subject-Token', KEYSTONE_TOKEN_VALUE)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_non_v3_token_response_is_rejected(self, mock_open, mock_wait):
        self._mock_flow(mock_open, mock_wait)
        # A v2 style body reaching the v3 endpoint is not something we can
        # rescope, so it must not be quietly accepted.
        self._stub_token_validation(body={'access': {}})
        plugin = self._plugin()

        self.assertRaises(
            exceptions.InvalidResponse,
            plugin.get_unscoped_auth_ref,
            self.session,
        )

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_reauthentication_does_not_reuse_a_stale_auth_ref(
        self, mock_open, mock_wait
    ):
        # auth_ref holds the previous, possibly scoped, token while we are
        # being asked to authenticate again. It must not be mistaken for a
        # usable unscoped token.
        self._mock_flow(mock_open, mock_wait)
        self._stub_token_validation()
        plugin = self._plugin()

        plugin.get_unscoped_auth_ref(self.session)
        plugin.auth_ref = plugin.get_unscoped_auth_ref(self.session)
        plugin.get_unscoped_auth_ref(self.session)

        self.assertEqual(3, mock_open.call_count)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_scoped_auth_rescopes_the_unscoped_token(
        self, mock_open, mock_wait
    ):
        self._mock_flow(mock_open, mock_wait)
        self._stub_token_validation()
        scoped_token = uuid.uuid4().hex
        self.requests_mock.post(
            f'{self.AUTH_URL}/auth/tokens',
            json=_token_body(),
            headers={'X-Subject-Token': scoped_token},
        )
        plugin = self._plugin(
            project_name='myproject', project_domain_name='Default'
        )

        auth_ref = plugin.get_auth_ref(self.session)

        self.assertEqual(scoped_token, auth_ref.auth_token)
