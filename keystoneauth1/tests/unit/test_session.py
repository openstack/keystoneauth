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

import itertools
import json
import logging
import sys
import uuid

import mock
import requests
import requests.auth
import six
from testtools import matchers

from keystoneauth1 import adapter
from keystoneauth1 import exceptions
from keystoneauth1 import plugin
from keystoneauth1 import session as client_session
from keystoneauth1.tests.unit import utils
from keystoneauth1 import token_endpoint


class RequestsAuth(requests.auth.AuthBase):

    def __init__(self, *args, **kwargs):
        super(RequestsAuth, self).__init__(*args, **kwargs)
        self.header_name = uuid.uuid4().hex
        self.header_val = uuid.uuid4().hex
        self.called = False

    def __call__(self, request):
        request.headers[self.header_name] = self.header_val
        self.called = True
        return request


class SessionTests(utils.TestCase):

    TEST_URL = 'http://127.0.0.1:5000/'

    def test_get(self):
        session = client_session.Session()
        self.stub_url('GET', text='response')
        resp = session.get(self.TEST_URL)

        self.assertEqual('GET', self.requests_mock.last_request.method)
        self.assertEqual(resp.text, 'response')
        self.assertTrue(resp.ok)

    def test_post(self):
        session = client_session.Session()
        self.stub_url('POST', text='response')
        resp = session.post(self.TEST_URL, json={'hello': 'world'})

        self.assertEqual('POST', self.requests_mock.last_request.method)
        self.assertEqual(resp.text, 'response')
        self.assertTrue(resp.ok)
        self.assertRequestBodyIs(json={'hello': 'world'})

    def test_head(self):
        session = client_session.Session()
        self.stub_url('HEAD')
        resp = session.head(self.TEST_URL)

        self.assertEqual('HEAD', self.requests_mock.last_request.method)
        self.assertTrue(resp.ok)
        self.assertRequestBodyIs('')

    def test_put(self):
        session = client_session.Session()
        self.stub_url('PUT', text='response')
        resp = session.put(self.TEST_URL, json={'hello': 'world'})

        self.assertEqual('PUT', self.requests_mock.last_request.method)
        self.assertEqual(resp.text, 'response')
        self.assertTrue(resp.ok)
        self.assertRequestBodyIs(json={'hello': 'world'})

    def test_delete(self):
        session = client_session.Session()
        self.stub_url('DELETE', text='response')
        resp = session.delete(self.TEST_URL)

        self.assertEqual('DELETE', self.requests_mock.last_request.method)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.text, 'response')

    def test_patch(self):
        session = client_session.Session()
        self.stub_url('PATCH', text='response')
        resp = session.patch(self.TEST_URL, json={'hello': 'world'})

        self.assertEqual('PATCH', self.requests_mock.last_request.method)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.text, 'response')
        self.assertRequestBodyIs(json={'hello': 'world'})

    def test_user_agent(self):
        session = client_session.Session()
        self.stub_url('GET', text='response')
        resp = session.get(self.TEST_URL)

        self.assertTrue(resp.ok)
        self.assertRequestHeaderEqual(
            'User-Agent',
            '%s %s' % ("run.py", client_session.DEFAULT_USER_AGENT))

        custom_agent = 'custom-agent/1.0'
        session = client_session.Session(user_agent=custom_agent)
        self.stub_url('GET', text='response')
        resp = session.get(self.TEST_URL)

        self.assertTrue(resp.ok)
        self.assertRequestHeaderEqual(
            'User-Agent',
            '%s %s' % (custom_agent, client_session.DEFAULT_USER_AGENT))

        resp = session.get(self.TEST_URL, headers={'User-Agent': 'new-agent'})
        self.assertTrue(resp.ok)
        self.assertRequestHeaderEqual('User-Agent', 'new-agent')

        resp = session.get(self.TEST_URL, headers={'User-Agent': 'new-agent'},
                           user_agent='overrides-agent')
        self.assertTrue(resp.ok)
        self.assertRequestHeaderEqual('User-Agent', 'overrides-agent')

        # If sys.argv is an empty list, then doesn't fail.
        with mock.patch.object(sys, 'argv', []):
            session = client_session.Session()
            resp = session.get(self.TEST_URL)
            self.assertTrue(resp.ok)
            self.assertRequestHeaderEqual(
                'User-Agent',
                client_session.DEFAULT_USER_AGENT)

        # If sys.argv[0] is an empty string, then doesn't fail.
        with mock.patch.object(sys, 'argv', ['']):
            session = client_session.Session()
            resp = session.get(self.TEST_URL)
            self.assertTrue(resp.ok)
            self.assertRequestHeaderEqual(
                'User-Agent',
                client_session.DEFAULT_USER_AGENT)

    def test_http_session_opts(self):
        session = client_session.Session(cert='cert.pem', timeout=5,
                                         verify='certs')

        FAKE_RESP = utils.TestResponse({'status_code': 200, 'text': 'resp'})
        RESP = mock.Mock(return_value=FAKE_RESP)

        with mock.patch.object(session.session, 'request', RESP) as mocked:
            session.post(self.TEST_URL, data='value')

            mock_args, mock_kwargs = mocked.call_args

            self.assertEqual(mock_args[0], 'POST')
            self.assertEqual(mock_args[1], self.TEST_URL)
            self.assertEqual(mock_kwargs['data'], 'value')
            self.assertEqual(mock_kwargs['cert'], 'cert.pem')
            self.assertEqual(mock_kwargs['verify'], 'certs')
            self.assertEqual(mock_kwargs['timeout'], 5)

    def test_not_found(self):
        session = client_session.Session()
        self.stub_url('GET', status_code=404)
        self.assertRaises(exceptions.NotFound, session.get, self.TEST_URL)

    def test_server_error(self):
        session = client_session.Session()
        self.stub_url('GET', status_code=500)
        self.assertRaises(exceptions.InternalServerError,
                          session.get, self.TEST_URL)

    def test_session_debug_output(self):
        """Test request and response headers in debug logs.

        in order to redact secure headers while debug is true.
        """
        session = client_session.Session(verify=False)
        headers = {'HEADERA': 'HEADERVALB'}
        security_headers = {'Authorization': uuid.uuid4().hex,
                            'X-Auth-Token': uuid.uuid4().hex,
                            'X-Subject-Token': uuid.uuid4().hex, }
        body = 'BODYRESPONSE'
        data = 'BODYDATA'
        all_headers = dict(
            itertools.chain(headers.items(), security_headers.items()))
        self.stub_url('POST', text=body, headers=all_headers)
        resp = session.post(self.TEST_URL, headers=all_headers, data=data)
        self.assertEqual(resp.status_code, 200)

        self.assertIn('curl', self.logger.output)
        self.assertIn('POST', self.logger.output)
        self.assertIn('--insecure', self.logger.output)
        self.assertIn(body, self.logger.output)
        self.assertIn("'%s'" % data, self.logger.output)

        for k, v in six.iteritems(headers):
            self.assertIn(k, self.logger.output)
            self.assertIn(v, self.logger.output)

        # Assert that response headers contains actual values and
        # only debug logs has been masked
        for k, v in six.iteritems(security_headers):
            self.assertIn('%s: {SHA1}' % k, self.logger.output)
            self.assertEqual(v, resp.headers[k])
            self.assertNotIn(v, self.logger.output)

    def test_logs_failed_output(self):
        """Test that output is logged even for failed requests."""
        session = client_session.Session()
        body = uuid.uuid4().hex

        self.stub_url('GET', text=body, status_code=400)
        resp = session.get(self.TEST_URL, raise_exc=False)

        self.assertEqual(resp.status_code, 400)
        self.assertIn(body, self.logger.output)

    def test_logging_cacerts(self):
        path_to_certs = '/path/to/certs'
        session = client_session.Session(verify=path_to_certs)

        self.stub_url('GET', text='text')
        session.get(self.TEST_URL)

        self.assertIn('--cacert', self.logger.output)
        self.assertIn(path_to_certs, self.logger.output)

    def test_connect_retries(self):
        self.stub_url('GET', exc=requests.exceptions.Timeout())

        session = client_session.Session()
        retries = 3

        with mock.patch('time.sleep') as m:
            self.assertRaises(exceptions.ConnectTimeout,
                              session.get,
                              self.TEST_URL, connect_retries=retries)

            self.assertEqual(retries, m.call_count)
            # 3 retries finishing with 2.0 means 0.5, 1.0 and 2.0
            m.assert_called_with(2.0)

        # we count retries so there will be one initial request + 3 retries
        self.assertThat(self.requests_mock.request_history,
                        matchers.HasLength(retries + 1))

    def test_uses_tcp_keepalive_by_default(self):
        session = client_session.Session()
        requests_session = session.session
        self.assertIsInstance(requests_session.adapters['http://'],
                              client_session.TCPKeepAliveAdapter)
        self.assertIsInstance(requests_session.adapters['https://'],
                              client_session.TCPKeepAliveAdapter)

    def test_does_not_set_tcp_keepalive_on_custom_sessions(self):
        mock_session = mock.Mock()
        client_session.Session(session=mock_session)
        self.assertFalse(mock_session.mount.called)

    def test_ssl_error_message(self):
        error = uuid.uuid4().hex

        self.stub_url('GET', exc=requests.exceptions.SSLError(error))
        session = client_session.Session()

        # The exception should contain the URL and details about the SSL error
        msg = 'SSL exception connecting to %(url)s: %(error)s' % {
            'url': self.TEST_URL, 'error': error}
        self.assertRaisesRegex(exceptions.SSLError,
                               msg,
                               session.get,
                               self.TEST_URL)


class RedirectTests(utils.TestCase):

    REDIRECT_CHAIN = ['http://myhost:3445/',
                      'http://anotherhost:6555/',
                      'http://thirdhost/',
                      'http://finaldestination:55/']

    DEFAULT_REDIRECT_BODY = 'Redirect'
    DEFAULT_RESP_BODY = 'Found'

    def setup_redirects(self, method='GET', status_code=305,
                        redirect_kwargs={}, final_kwargs={}):
        redirect_kwargs.setdefault('text', self.DEFAULT_REDIRECT_BODY)

        for s, d in zip(self.REDIRECT_CHAIN, self.REDIRECT_CHAIN[1:]):
            self.requests_mock.register_uri(method, s, status_code=status_code,
                                            headers={'Location': d},
                                            **redirect_kwargs)

        final_kwargs.setdefault('status_code', 200)
        final_kwargs.setdefault('text', self.DEFAULT_RESP_BODY)
        self.requests_mock.register_uri(method, self.REDIRECT_CHAIN[-1],
                                        **final_kwargs)

    def assertResponse(self, resp):
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, self.DEFAULT_RESP_BODY)

    def test_basic_get(self):
        session = client_session.Session()
        self.setup_redirects()
        resp = session.get(self.REDIRECT_CHAIN[-2])
        self.assertResponse(resp)

    def test_basic_post_keeps_correct_method(self):
        session = client_session.Session()
        self.setup_redirects(method='POST', status_code=301)
        resp = session.post(self.REDIRECT_CHAIN[-2])
        self.assertResponse(resp)

    def test_redirect_forever(self):
        session = client_session.Session(redirect=True)
        self.setup_redirects()
        resp = session.get(self.REDIRECT_CHAIN[0])
        self.assertResponse(resp)
        self.assertTrue(len(resp.history), len(self.REDIRECT_CHAIN))

    def test_no_redirect(self):
        session = client_session.Session(redirect=False)
        self.setup_redirects()
        resp = session.get(self.REDIRECT_CHAIN[0])
        self.assertEqual(resp.status_code, 305)
        self.assertEqual(resp.url, self.REDIRECT_CHAIN[0])

    def test_redirect_limit(self):
        self.setup_redirects()
        for i in (1, 2):
            session = client_session.Session(redirect=i)
            resp = session.get(self.REDIRECT_CHAIN[0])
            self.assertEqual(resp.status_code, 305)
            self.assertEqual(resp.url, self.REDIRECT_CHAIN[i])
            self.assertEqual(resp.text, self.DEFAULT_REDIRECT_BODY)

    def test_history_matches_requests(self):
        self.setup_redirects(status_code=301)
        session = client_session.Session(redirect=True)
        req_resp = requests.get(self.REDIRECT_CHAIN[0],
                                allow_redirects=True)

        ses_resp = session.get(self.REDIRECT_CHAIN[0])

        self.assertEqual(len(req_resp.history), len(ses_resp.history))

        for r, s in zip(req_resp.history, ses_resp.history):
            self.assertEqual(r.url, s.url)
            self.assertEqual(r.status_code, s.status_code)

    def test_permanent_redirect_308(self):
        session = client_session.Session()
        self.setup_redirects(status_code=308)
        resp = session.get(self.REDIRECT_CHAIN[-2])
        self.assertResponse(resp)


class AuthPlugin(plugin.BaseAuthPlugin):
    """Very simple debug authentication plugin.

    Takes Parameters such that it can throw exceptions at the right times.
    """

    TEST_TOKEN = utils.TestCase.TEST_TOKEN
    TEST_USER_ID = 'aUser'
    TEST_PROJECT_ID = 'aProject'

    SERVICE_URLS = {
        'identity': {'public': 'http://identity-public:1111/v2.0',
                     'admin': 'http://identity-admin:1111/v2.0'},
        'compute': {'public': 'http://compute-public:2222/v1.0',
                    'admin': 'http://compute-admin:2222/v1.0'},
        'image': {'public': 'http://image-public:3333/v2.0',
                  'admin': 'http://image-admin:3333/v2.0'}
    }

    def __init__(self, token=TEST_TOKEN, invalidate=True):
        self.token = token
        self._invalidate = invalidate

    def get_token(self, session):
        return self.token

    def get_endpoint(self, session, service_type=None, interface=None,
                     **kwargs):
        try:
            return self.SERVICE_URLS[service_type][interface]
        except (KeyError, AttributeError):
            return None

    def invalidate(self):
        return self._invalidate

    def get_user_id(self, session):
        return self.TEST_USER_ID

    def get_project_id(self, session):
        return self.TEST_PROJECT_ID


class CalledAuthPlugin(plugin.BaseAuthPlugin):

    ENDPOINT = 'http://fakeendpoint/'
    USER_ID = uuid.uuid4().hex
    PROJECT_ID = uuid.uuid4().hex

    def __init__(self, invalidate=True):
        self.get_token_called = False
        self.get_endpoint_called = False
        self.endpoint_arguments = {}
        self.invalidate_called = False
        self.get_project_id_called = False
        self.get_user_id_called = False
        self._invalidate = invalidate

    def get_token(self, session):
        self.get_token_called = True
        return utils.TestCase.TEST_TOKEN

    def get_endpoint(self, session, **kwargs):
        self.get_endpoint_called = True
        self.endpoint_arguments = kwargs
        return self.ENDPOINT

    def invalidate(self):
        self.invalidate_called = True
        return self._invalidate

    def get_project_id(self, session, **kwargs):
        self.get_project_id_called = True
        return self.PROJECT_ID

    def get_user_id(self, session, **kwargs):
        self.get_user_id_called = True
        return self.USER_ID


class SessionAuthTests(utils.TestCase):

    TEST_URL = 'http://127.0.0.1:5000/'
    TEST_JSON = {'hello': 'world'}

    def stub_service_url(self, service_type, interface, path,
                         method='GET', **kwargs):
        base_url = AuthPlugin.SERVICE_URLS[service_type][interface]
        uri = "%s/%s" % (base_url.rstrip('/'), path.lstrip('/'))

        self.requests_mock.register_uri(method, uri, **kwargs)

    def test_auth_plugin_default_with_plugin(self):
        self.stub_url('GET', base_url=self.TEST_URL, json=self.TEST_JSON)

        # if there is an auth_plugin then it should default to authenticated
        auth = AuthPlugin()
        sess = client_session.Session(auth=auth)
        resp = sess.get(self.TEST_URL)
        self.assertEqual(resp.json(), self.TEST_JSON)

        self.assertRequestHeaderEqual('X-Auth-Token', AuthPlugin.TEST_TOKEN)

    def test_auth_plugin_disable(self):
        self.stub_url('GET', base_url=self.TEST_URL, json=self.TEST_JSON)

        auth = AuthPlugin()
        sess = client_session.Session(auth=auth)
        resp = sess.get(self.TEST_URL, authenticated=False)
        self.assertEqual(resp.json(), self.TEST_JSON)

        self.assertRequestHeaderEqual('X-Auth-Token', None)

    def test_service_type_urls(self):
        service_type = 'compute'
        interface = 'public'
        path = '/instances'
        status = 200
        body = 'SUCCESS'

        self.stub_service_url(service_type=service_type,
                              interface=interface,
                              path=path,
                              status_code=status,
                              text=body)

        sess = client_session.Session(auth=AuthPlugin())
        resp = sess.get(path,
                        endpoint_filter={'service_type': service_type,
                                         'interface': interface})

        self.assertEqual(self.requests_mock.last_request.url,
                         AuthPlugin.SERVICE_URLS['compute']['public'] + path)
        self.assertEqual(resp.text, body)
        self.assertEqual(resp.status_code, status)

    def test_service_url_raises_if_no_auth_plugin(self):
        sess = client_session.Session()
        self.assertRaises(exceptions.MissingAuthPlugin,
                          sess.get, '/path',
                          endpoint_filter={'service_type': 'compute',
                                           'interface': 'public'})

    def test_service_url_raises_if_no_url_returned(self):
        sess = client_session.Session(auth=AuthPlugin())
        self.assertRaises(exceptions.EndpointNotFound,
                          sess.get, '/path',
                          endpoint_filter={'service_type': 'unknown',
                                           'interface': 'public'})

    def test_raises_exc_only_when_asked(self):
        # A request that returns a HTTP error should by default raise an
        # exception by default, if you specify raise_exc=False then it will not
        self.requests_mock.get(self.TEST_URL, status_code=401)

        sess = client_session.Session()
        self.assertRaises(exceptions.Unauthorized, sess.get, self.TEST_URL)

        resp = sess.get(self.TEST_URL, raise_exc=False)
        self.assertEqual(401, resp.status_code)

    def test_passed_auth_plugin(self):
        passed = CalledAuthPlugin()
        sess = client_session.Session()

        self.requests_mock.get(CalledAuthPlugin.ENDPOINT + 'path',
                               status_code=200)
        endpoint_filter = {'service_type': 'identity'}

        # no plugin with authenticated won't work
        self.assertRaises(exceptions.MissingAuthPlugin, sess.get, 'path',
                          authenticated=True)

        # no plugin with an endpoint filter won't work
        self.assertRaises(exceptions.MissingAuthPlugin, sess.get, 'path',
                          authenticated=False, endpoint_filter=endpoint_filter)

        resp = sess.get('path', auth=passed, endpoint_filter=endpoint_filter)

        self.assertEqual(200, resp.status_code)
        self.assertTrue(passed.get_endpoint_called)
        self.assertTrue(passed.get_token_called)

    def test_passed_auth_plugin_overrides(self):
        fixed = CalledAuthPlugin()
        passed = CalledAuthPlugin()

        sess = client_session.Session(fixed)

        self.requests_mock.get(CalledAuthPlugin.ENDPOINT + 'path',
                               status_code=200)

        resp = sess.get('path', auth=passed,
                        endpoint_filter={'service_type': 'identity'})

        self.assertEqual(200, resp.status_code)
        self.assertTrue(passed.get_endpoint_called)
        self.assertTrue(passed.get_token_called)
        self.assertFalse(fixed.get_endpoint_called)
        self.assertFalse(fixed.get_token_called)

    def test_requests_auth_plugin(self):
        sess = client_session.Session()
        requests_auth = RequestsAuth()

        self.requests_mock.get(self.TEST_URL, text='resp')

        sess.get(self.TEST_URL, requests_auth=requests_auth)
        last = self.requests_mock.last_request

        self.assertEqual(requests_auth.header_val,
                         last.headers[requests_auth.header_name])
        self.assertTrue(requests_auth.called)

    def test_reauth_called(self):
        auth = CalledAuthPlugin(invalidate=True)
        sess = client_session.Session(auth=auth)

        self.requests_mock.get(self.TEST_URL,
                               [{'text': 'Failed', 'status_code': 401},
                                {'text': 'Hello', 'status_code': 200}])

        # allow_reauth=True is the default
        resp = sess.get(self.TEST_URL, authenticated=True)

        self.assertEqual(200, resp.status_code)
        self.assertEqual('Hello', resp.text)
        self.assertTrue(auth.invalidate_called)

    def test_reauth_not_called(self):
        auth = CalledAuthPlugin(invalidate=True)
        sess = client_session.Session(auth=auth)

        self.requests_mock.get(self.TEST_URL,
                               [{'text': 'Failed', 'status_code': 401},
                                {'text': 'Hello', 'status_code': 200}])

        self.assertRaises(exceptions.Unauthorized, sess.get, self.TEST_URL,
                          authenticated=True, allow_reauth=False)
        self.assertFalse(auth.invalidate_called)

    def test_endpoint_override_overrides_filter(self):
        auth = CalledAuthPlugin()
        sess = client_session.Session(auth=auth)

        override_base = 'http://mytest/'
        path = 'path'
        override_url = override_base + path
        resp_text = uuid.uuid4().hex

        self.requests_mock.get(override_url, text=resp_text)

        resp = sess.get(path,
                        endpoint_override=override_base,
                        endpoint_filter={'service_type': 'identity'})

        self.assertEqual(resp_text, resp.text)
        self.assertEqual(override_url, self.requests_mock.last_request.url)

        self.assertTrue(auth.get_token_called)
        self.assertFalse(auth.get_endpoint_called)

        self.assertFalse(auth.get_user_id_called)
        self.assertFalse(auth.get_project_id_called)

    def test_endpoint_override_ignore_full_url(self):
        auth = CalledAuthPlugin()
        sess = client_session.Session(auth=auth)

        path = 'path'
        url = self.TEST_URL + path

        resp_text = uuid.uuid4().hex
        self.requests_mock.get(url, text=resp_text)

        resp = sess.get(url,
                        endpoint_override='http://someother.url',
                        endpoint_filter={'service_type': 'identity'})

        self.assertEqual(resp_text, resp.text)
        self.assertEqual(url, self.requests_mock.last_request.url)

        self.assertTrue(auth.get_token_called)
        self.assertFalse(auth.get_endpoint_called)

        self.assertFalse(auth.get_user_id_called)
        self.assertFalse(auth.get_project_id_called)

    def test_endpoint_override_does_id_replacement(self):
        auth = CalledAuthPlugin()
        sess = client_session.Session(auth=auth)

        override_base = 'http://mytest/%(project_id)s/%(user_id)s'
        path = 'path'
        replacements = {'user_id': CalledAuthPlugin.USER_ID,
                        'project_id': CalledAuthPlugin.PROJECT_ID}
        override_url = override_base % replacements + '/' + path
        resp_text = uuid.uuid4().hex

        self.requests_mock.get(override_url, text=resp_text)

        resp = sess.get(path,
                        endpoint_override=override_base,
                        endpoint_filter={'service_type': 'identity'})

        self.assertEqual(resp_text, resp.text)
        self.assertEqual(override_url, self.requests_mock.last_request.url)

        self.assertTrue(auth.get_token_called)
        self.assertTrue(auth.get_user_id_called)
        self.assertTrue(auth.get_project_id_called)
        self.assertFalse(auth.get_endpoint_called)

    def test_endpoint_override_fails_to_replace_if_none(self):
        # The token_endpoint plugin doesn't know user_id or project_id
        auth = token_endpoint.Token(uuid.uuid4().hex, uuid.uuid4().hex)
        sess = client_session.Session(auth=auth)

        override_base = 'http://mytest/%(project_id)s'

        e = self.assertRaises(ValueError,
                              sess.get,
                              '/path',
                              endpoint_override=override_base,
                              endpoint_filter={'service_type': 'identity'})

        self.assertIn('project_id', str(e))
        override_base = 'http://mytest/%(user_id)s'

        e = self.assertRaises(ValueError,
                              sess.get,
                              '/path',
                              endpoint_override=override_base,
                              endpoint_filter={'service_type': 'identity'})
        self.assertIn('user_id', str(e))

    def test_endpoint_override_fails_to_do_unknown_replacement(self):
        auth = CalledAuthPlugin()
        sess = client_session.Session(auth=auth)

        override_base = 'http://mytest/%(unknown_id)s'

        e = self.assertRaises(AttributeError,
                              sess.get,
                              '/path',
                              endpoint_override=override_base,
                              endpoint_filter={'service_type': 'identity'})
        self.assertIn('unknown_id', str(e))

    def test_user_and_project_id(self):
        auth = AuthPlugin()
        sess = client_session.Session(auth=auth)

        self.assertEqual(auth.TEST_USER_ID, sess.get_user_id())
        self.assertEqual(auth.TEST_PROJECT_ID, sess.get_project_id())

    def test_logger_object_passed(self):
        logger = logging.getLogger(uuid.uuid4().hex)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        io = six.StringIO()
        handler = logging.StreamHandler(io)
        logger.addHandler(handler)

        auth = AuthPlugin()
        sess = client_session.Session(auth=auth)
        response = uuid.uuid4().hex

        self.stub_url('GET',
                      text=response,
                      headers={'Content-Type': 'text/html'})

        resp = sess.get(self.TEST_URL, logger=logger)

        self.assertEqual(response, resp.text)
        output = io.getvalue()

        self.assertIn(self.TEST_URL, output)
        self.assertIn(response, output)

        self.assertNotIn(self.TEST_URL, self.logger.output)
        self.assertNotIn(response, self.logger.output)


class AdapterTest(utils.TestCase):

    SERVICE_TYPE = uuid.uuid4().hex
    SERVICE_NAME = uuid.uuid4().hex
    INTERFACE = uuid.uuid4().hex
    REGION_NAME = uuid.uuid4().hex
    USER_AGENT = uuid.uuid4().hex
    VERSION = uuid.uuid4().hex
    ALLOW = {'allow_deprecated': False,
             'allow_experimental': True,
             'allow_unknown': True}

    TEST_URL = CalledAuthPlugin.ENDPOINT

    def _create_loaded_adapter(self):
        auth = CalledAuthPlugin()
        sess = client_session.Session()
        return adapter.Adapter(sess,
                               auth=auth,
                               service_type=self.SERVICE_TYPE,
                               service_name=self.SERVICE_NAME,
                               interface=self.INTERFACE,
                               region_name=self.REGION_NAME,
                               user_agent=self.USER_AGENT,
                               version=self.VERSION,
                               allow=self.ALLOW)

    def _verify_endpoint_called(self, adpt):
        self.assertEqual(self.SERVICE_TYPE,
                         adpt.auth.endpoint_arguments['service_type'])
        self.assertEqual(self.SERVICE_NAME,
                         adpt.auth.endpoint_arguments['service_name'])
        self.assertEqual(self.INTERFACE,
                         adpt.auth.endpoint_arguments['interface'])
        self.assertEqual(self.REGION_NAME,
                         adpt.auth.endpoint_arguments['region_name'])
        self.assertEqual(self.VERSION,
                         adpt.auth.endpoint_arguments['version'])

    def test_setting_variables_on_request(self):
        response = uuid.uuid4().hex
        self.stub_url('GET', text=response)
        adpt = self._create_loaded_adapter()
        resp = adpt.get('/')
        self.assertEqual(resp.text, response)

        self._verify_endpoint_called(adpt)
        self.assertEqual(self.ALLOW,
                         adpt.auth.endpoint_arguments['allow'])
        self.assertTrue(adpt.auth.get_token_called)
        self.assertRequestHeaderEqual('User-Agent', self.USER_AGENT)

    def test_setting_variables_on_get_endpoint(self):
        adpt = self._create_loaded_adapter()
        url = adpt.get_endpoint()

        self.assertEqual(self.TEST_URL, url)
        self._verify_endpoint_called(adpt)

    def test_legacy_binding(self):
        key = uuid.uuid4().hex
        val = uuid.uuid4().hex
        response = json.dumps({key: val})

        self.stub_url('GET', text=response)

        auth = CalledAuthPlugin()
        sess = client_session.Session(auth=auth)
        adpt = adapter.LegacyJsonAdapter(sess,
                                         service_type=self.SERVICE_TYPE,
                                         user_agent=self.USER_AGENT)

        resp, body = adpt.get('/')
        self.assertEqual(self.SERVICE_TYPE,
                         auth.endpoint_arguments['service_type'])
        self.assertEqual(resp.text, response)
        self.assertEqual(val, body[key])

    def test_legacy_binding_non_json_resp(self):
        response = uuid.uuid4().hex
        self.stub_url('GET', text=response,
                      headers={'Content-Type': 'text/html'})

        auth = CalledAuthPlugin()
        sess = client_session.Session(auth=auth)
        adpt = adapter.LegacyJsonAdapter(sess,
                                         service_type=self.SERVICE_TYPE,
                                         user_agent=self.USER_AGENT)

        resp, body = adpt.get('/')
        self.assertEqual(self.SERVICE_TYPE,
                         auth.endpoint_arguments['service_type'])
        self.assertEqual(resp.text, response)
        self.assertIsNone(body)

    def test_methods(self):
        sess = client_session.Session()
        adpt = adapter.Adapter(sess)
        url = 'http://url'

        for method in ['get', 'head', 'post', 'put', 'patch', 'delete']:
            with mock.patch.object(adpt, 'request') as m:
                getattr(adpt, method)(url)
                m.assert_called_once_with(url, method.upper())

    def test_setting_endpoint_override(self):
        endpoint_override = 'http://overrideurl'
        path = '/path'
        endpoint_url = endpoint_override + path

        auth = CalledAuthPlugin()
        sess = client_session.Session(auth=auth)
        adpt = adapter.Adapter(sess, endpoint_override=endpoint_override)

        response = uuid.uuid4().hex
        self.requests_mock.get(endpoint_url, text=response)

        resp = adpt.get(path)

        self.assertEqual(response, resp.text)
        self.assertEqual(endpoint_url, self.requests_mock.last_request.url)

        self.assertEqual(endpoint_override, adpt.get_endpoint())

    def test_adapter_invalidate(self):
        auth = CalledAuthPlugin()
        sess = client_session.Session()
        adpt = adapter.Adapter(sess, auth=auth)

        adpt.invalidate()

        self.assertTrue(auth.invalidate_called)

    def test_adapter_get_token(self):
        auth = CalledAuthPlugin()
        sess = client_session.Session()
        adpt = adapter.Adapter(sess, auth=auth)

        self.assertEqual(self.TEST_TOKEN, adpt.get_token())
        self.assertTrue(auth.get_token_called)

    def test_adapter_connect_retries(self):
        retries = 2
        sess = client_session.Session()
        adpt = adapter.Adapter(sess, connect_retries=retries)

        self.stub_url('GET', exc=requests.exceptions.ConnectionError())

        with mock.patch('time.sleep') as m:
            self.assertRaises(exceptions.ConnectionError,
                              adpt.get, self.TEST_URL)
            self.assertEqual(retries, m.call_count)

        # we count retries so there will be one initial request + 2 retries
        self.assertThat(self.requests_mock.request_history,
                        matchers.HasLength(retries + 1))

    def test_user_and_project_id(self):
        auth = AuthPlugin()
        sess = client_session.Session()
        adpt = adapter.Adapter(sess, auth=auth)

        self.assertEqual(auth.TEST_USER_ID, adpt.get_user_id())
        self.assertEqual(auth.TEST_PROJECT_ID, adpt.get_project_id())

    def test_logger_object_passed(self):
        logger = logging.getLogger(uuid.uuid4().hex)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        io = six.StringIO()
        handler = logging.StreamHandler(io)
        logger.addHandler(handler)

        auth = AuthPlugin()
        sess = client_session.Session(auth=auth)
        adpt = adapter.Adapter(sess, auth=auth, logger=logger)

        response = uuid.uuid4().hex

        self.stub_url('GET', text=response,
                      headers={'Content-Type': 'text/html'})

        resp = adpt.get(self.TEST_URL, logger=logger)

        self.assertEqual(response, resp.text)
        output = io.getvalue()

        self.assertIn(self.TEST_URL, output)
        self.assertIn(response, output)

        self.assertNotIn(self.TEST_URL, self.logger.output)
        self.assertNotIn(response, self.logger.output)

    def test_unknown_connection_error(self):
        self.stub_url('GET', exc=requests.exceptions.RequestException)
        self.assertRaises(exceptions.UnknownConnectionError,
                          client_session.Session().request,
                          self.TEST_URL,
                          'GET')

    def test_additional_headers(self):
        session_key = uuid.uuid4().hex
        session_val = uuid.uuid4().hex
        adapter_key = uuid.uuid4().hex
        adapter_val = uuid.uuid4().hex
        request_key = uuid.uuid4().hex
        request_val = uuid.uuid4().hex
        text = uuid.uuid4().hex

        url = 'http://keystone.test.com'
        self.requests_mock.get(url, text=text)

        sess = client_session.Session(
            additional_headers={session_key: session_val})
        adap = adapter.Adapter(session=sess,
                               additional_headers={adapter_key: adapter_val})
        resp = adap.get(url, headers={request_key: request_val})

        request = self.requests_mock.last_request

        self.assertEqual(resp.text, text)
        self.assertEqual(session_val, request.headers[session_key])
        self.assertEqual(adapter_val, request.headers[adapter_key])
        self.assertEqual(request_val, request.headers[request_key])

    def test_additional_headers_overrides(self):
        header = uuid.uuid4().hex
        session_val = uuid.uuid4().hex
        adapter_val = uuid.uuid4().hex
        request_val = uuid.uuid4().hex

        url = 'http://keystone.test.com'
        self.requests_mock.get(url)

        sess = client_session.Session(additional_headers={header: session_val})
        adap = adapter.Adapter(session=sess)

        adap.get(url)
        self.assertEqual(session_val,
                         self.requests_mock.last_request.headers[header])

        adap.additional_headers[header] = adapter_val
        adap.get(url)
        self.assertEqual(adapter_val,
                         self.requests_mock.last_request.headers[header])

        adap.get(url, headers={header: request_val})
        self.assertEqual(request_val,
                         self.requests_mock.last_request.headers[header])


class TCPKeepAliveAdapterTest(utils.TestCase):

    def setUp(self):
        super(TCPKeepAliveAdapterTest, self).setUp()
        self.init_poolmanager = self.patch(
            client_session.requests.adapters.HTTPAdapter,
            'init_poolmanager')
        self.constructor = self.patch(
            client_session.TCPKeepAliveAdapter, '__init__', lambda self: None)

    def test_init_poolmanager_with_requests_lesser_than_2_4_1(self):
        self.patch(client_session, 'REQUESTS_VERSION', (2, 4, 0))
        given_adapter = client_session.TCPKeepAliveAdapter()

        # when pool manager is initialized
        given_adapter.init_poolmanager(1, 2, 3)

        # then no socket_options are given
        self.init_poolmanager.assert_called_once_with(1, 2, 3)

    def test_init_poolmanager_with_basic_options(self):
        self.patch(client_session, 'REQUESTS_VERSION', (2, 4, 1))
        socket = self.patch_socket_with_options(
            ['IPPROTO_TCP', 'TCP_NODELAY', 'SOL_SOCKET', 'SO_KEEPALIVE'])
        given_adapter = client_session.TCPKeepAliveAdapter()

        # when pool manager is initialized
        given_adapter.init_poolmanager(1, 2, 3)

        # then no socket_options are given
        self.init_poolmanager.assert_called_once_with(
            1, 2, 3, socket_options=[
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)])

    def test_init_poolmanager_with_tcp_keepidle(self):
        self.patch(client_session, 'REQUESTS_VERSION', (2, 4, 1))
        socket = self.patch_socket_with_options(
            ['IPPROTO_TCP', 'TCP_NODELAY', 'SOL_SOCKET', 'SO_KEEPALIVE',
             'TCP_KEEPIDLE'])
        given_adapter = client_session.TCPKeepAliveAdapter()

        # when pool manager is initialized
        given_adapter.init_poolmanager(1, 2, 3)

        # then socket_options are given
        self.init_poolmanager.assert_called_once_with(
            1, 2, 3, socket_options=[
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)])

    def test_init_poolmanager_with_tcp_keepcnt(self):
        self.patch(client_session, 'REQUESTS_VERSION', (2, 4, 1))
        self.patch(client_session.utils, 'is_windows_linux_subsystem', False)
        socket = self.patch_socket_with_options(
            ['IPPROTO_TCP', 'TCP_NODELAY', 'SOL_SOCKET', 'SO_KEEPALIVE',
             'TCP_KEEPCNT'])
        given_adapter = client_session.TCPKeepAliveAdapter()

        # when pool manager is initialized
        given_adapter.init_poolmanager(1, 2, 3)

        # then socket_options are given
        self.init_poolmanager.assert_called_once_with(
            1, 2, 3, socket_options=[
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)])

    def test_init_poolmanager_with_tcp_keepcnt_on_windows(self):
        self.patch(client_session, 'REQUESTS_VERSION', (2, 4, 1))
        self.patch(client_session.utils, 'is_windows_linux_subsystem', True)
        socket = self.patch_socket_with_options(
            ['IPPROTO_TCP', 'TCP_NODELAY', 'SOL_SOCKET', 'SO_KEEPALIVE',
             'TCP_KEEPCNT'])
        given_adapter = client_session.TCPKeepAliveAdapter()

        # when pool manager is initialized
        given_adapter.init_poolmanager(1, 2, 3)

        # then socket_options are given
        self.init_poolmanager.assert_called_once_with(
            1, 2, 3, socket_options=[
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)])

    def test_init_poolmanager_with_tcp_keepintvl(self):
        self.patch(client_session, 'REQUESTS_VERSION', (2, 4, 1))
        socket = self.patch_socket_with_options(
            ['IPPROTO_TCP', 'TCP_NODELAY', 'SOL_SOCKET', 'SO_KEEPALIVE',
             'TCP_KEEPINTVL'])
        given_adapter = client_session.TCPKeepAliveAdapter()

        # when pool manager is initialized
        given_adapter.init_poolmanager(1, 2, 3)

        # then socket_options are given
        self.init_poolmanager.assert_called_once_with(
            1, 2, 3, socket_options=[
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)])

    def test_init_poolmanager_with_given_optionsl(self):
        self.patch(client_session, 'REQUESTS_VERSION', (2, 4, 1))
        given_adapter = client_session.TCPKeepAliveAdapter()
        given_options = object()

        # when pool manager is initialized
        given_adapter.init_poolmanager(1, 2, 3, socket_options=given_options)

        # then socket_options are given
        self.init_poolmanager.assert_called_once_with(
            1, 2, 3, socket_options=given_options)

    def patch_socket_with_options(self, option_names):
        # to mock socket module with exactly the attributes I want I create
        # a class with that attributes
        socket = type('socket', (object,),
                      {name: 'socket.' + name for name in option_names})
        return self.patch(client_session, 'socket', socket)

    def patch(self, target, name, *args, **kwargs):
        context = mock.patch.object(target, name, *args, **kwargs)
        patch = context.start()
        self.addCleanup(context.stop)
        return patch
