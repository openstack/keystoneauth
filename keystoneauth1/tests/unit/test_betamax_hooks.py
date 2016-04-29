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

import betamax
import json
from requests import models
import testtools

try:
    from requests.packages.urllib3._collections import HTTPHeaderDict
except ImportError:
    from betamax.headers import HTTPHeaderDict

from keystoneauth1.fixture import hooks


class TestBetamaxHooks(testtools.TestCase):

    def test_pre_record_hook(self):
        with betamax.Betamax.configure() as config:
            config.before_record(callback=hooks.pre_record_hook)

        cassette = betamax.cassette.Cassette(
            'test_pre_record_hook', 'json', record_mode=None,
            cassette_library_dir='keystoneauth1/tests/unit/data')

        # Create a new object to serialize
        r = models.Response()
        r.status_code = 200
        r.reason = 'OK'
        r.encoding = 'utf-8'
        r.headers = {}
        r.url = 'http://192.168.0.19:35357/'

        body_content = {
            'auth': {
                'passwordCredentials': {
                    'username': 'user',
                    'password': 'password'
                },
                'tenantName': 'dummy',
            },
            'access': {
                'token': {
                    'expires': '2001-01-01T00:00:00Z'
                }
            }
        }

        body_content = {
            'body': {
                'string': json.dumps(body_content),
                'encoding': 'utf-8',
            }
        }

        betamax.util.add_urllib3_response(
            body_content, r,
            HTTPHeaderDict({'Accept': 'application/json'}))
        response = r

        # Create an associated request
        r = models.Request()
        r.method = 'GET'
        r.url = 'http://192.168.0.19:35357/'
        r.headers = {}
        r.data = {}
        response.request = r.prepare()
        response.request.headers.update(
            {'User-Agent': 'betamax/test header'}
        )

        response.request.body = json.dumps({
            'auth': {
                'passwordCredentials': {
                    'username': 'user',
                    'password': 'password'
                },
                'tenantName': 'dummy'
            }
        })

        interaction = cassette.save_interaction(response, response.request)

        # check that all values have been masked
        response_content = json.loads(
            interaction.data['response']['body']['string'])
        self.assertEqual(
            response_content['access']['token']['expires'],
            u'9999-12-31T23:59:59Z')
        self.assertEqual(response_content['auth']['tenantName'], u'dummy')
        self.assertEqual(
            response_content['auth']['passwordCredentials']['username'],
            u'dummy')
        self.assertEqual(
            response_content['auth']['passwordCredentials']['password'],
            u'********')

        request_content = json.loads(
            interaction.data['response']['body']['string'])
        self.assertEqual(request_content['auth']['tenantName'], u'dummy')
        self.assertEqual(
            request_content['auth']['passwordCredentials']['username'],
            u'dummy')
        self.assertEqual(
            request_content['auth']['passwordCredentials']['password'],
            u'********')
