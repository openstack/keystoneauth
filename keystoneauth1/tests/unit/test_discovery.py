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

import json
import re

from testtools import matchers

from keystoneauth1 import discover
from keystoneauth1 import fixture
from keystoneauth1 import session
from keystoneauth1.tests.unit import utils


BASE_HOST = 'http://keystone.example.com'
BASE_URL = "%s:5000/" % BASE_HOST
UPDATED = '2013-03-06T00:00:00Z'

TEST_SERVICE_CATALOG = [{
    "endpoints": [{
        "adminURL": "%s:8774/v1.0" % BASE_HOST,
        "region": "RegionOne",
        "internalURL": "%s://127.0.0.1:8774/v1.0" % BASE_HOST,
        "publicURL": "%s:8774/v1.0/" % BASE_HOST
    }],
    "type": "nova_compat",
    "name": "nova_compat"
}, {
    "endpoints": [{
        "adminURL": "http://nova/novapi/admin",
        "region": "RegionOne",
        "internalURL": "http://nova/novapi/internal",
        "publicURL": "http://nova/novapi/public"
    }],
    "type": "compute",
    "name": "nova"
}, {
    "endpoints": [{
        "adminURL": "http://glance/glanceapi/admin",
        "region": "RegionOne",
        "internalURL": "http://glance/glanceapi/internal",
        "publicURL": "http://glance/glanceapi/public"
    }],
    "type": "image",
    "name": "glance"
}, {
    "endpoints": [{
        "adminURL": "%s:35357/v2.0" % BASE_HOST,
        "region": "RegionOne",
        "internalURL": "%s:5000/v2.0" % BASE_HOST,
        "publicURL": "%s:5000/v2.0" % BASE_HOST
    }],
    "type": "identity",
    "name": "keystone"
}, {
    "endpoints": [{
        "adminURL": "http://swift/swiftapi/admin",
        "region": "RegionOne",
        "internalURL": "http://swift/swiftapi/internal",
        "publicURL": "http://swift/swiftapi/public"
    }],
    "type": "object-store",
    "name": "swift"
}]

V2_URL = "%sv2.0" % BASE_URL
V2_VERSION = fixture.V2Discovery(V2_URL)
V2_VERSION.updated_str = UPDATED

V2_AUTH_RESPONSE = json.dumps({
    "access": {
        "token": {
            "expires": "2020-01-01T00:00:10.000123Z",
            "id": 'fakeToken',
            "tenant": {
                "id": '1'
            },
        },
        "user": {
            "id": 'test'
        },
        "serviceCatalog": TEST_SERVICE_CATALOG,
    },
})

V3_URL = "%sv3" % BASE_URL
V3_VERSION = fixture.V3Discovery(V3_URL)
V3_MEDIA_TYPES = V3_VERSION.media_types
V3_VERSION.updated_str = UPDATED

V3_AUTH_RESPONSE = json.dumps({
    "token": {
        "methods": [
            "token",
            "password"
        ],

        "expires_at": "2020-01-01T00:00:10.000123Z",
        "project": {
            "domain": {
                "id": '1',
                "name": 'test-domain'
            },
            "id": '1',
            "name": 'test-project'
        },
        "user": {
            "domain": {
                "id": '1',
                "name": 'test-domain'
            },
            "id": '1',
            "name": 'test-user'
        },
        "issued_at": "2013-05-29T16:55:21.468960Z",
    },
})

CINDER_EXAMPLES = {
    "versions": [
        {
            "status": "CURRENT",
            "updated": "2012-01-04T11:33:21Z",
            "id": "v1.0",
            "links": [
                {
                    "href": "%sv1/" % BASE_URL,
                    "rel": "self"
                }
            ]
        },
        {
            "status": "CURRENT",
            "updated": "2012-11-21T11:33:21Z",
            "id": "v2.0",
            "links": [
                {
                    "href": "%sv2/" % BASE_URL,
                    "rel": "self"
                }
            ]
        },
        {
            "status": "CURRENT",
            "updated": "2012-11-21T11:33:21Z",
            "id": "v3.0",
            "version": "3.27",
            "min_version": "3.0",
            "links": [
                {
                    "href": BASE_URL,
                    "rel": "collection"
                },
                {
                    "href": "%sv3/" % BASE_URL,
                    "rel": "self"
                }
            ]
        }
    ]
}

GLANCE_EXAMPLES = {
    "versions": [
        {
            "status": "CURRENT",
            "id": "v2.2",
            "links": [
                {
                    "href": "%sv2/" % BASE_URL,
                    "rel": "self"
                }
            ]
        },
        {
            "status": "SUPPORTED",
            "id": "v2.1",
            "links": [
                {
                    "href": "%sv2/" % BASE_URL,
                    "rel": "self"
                }
            ]
        },
        {
            "status": "SUPPORTED",
            "id": "v2.0",
            "links": [
                {
                    "href": "%sv2/" % BASE_URL,
                    "rel": "self"
                }
            ]
        },
        {
            "status": "CURRENT",
            "id": "v1.1",
            "links": [
                {
                    "href": "%sv1/" % BASE_URL,
                    "rel": "self"
                }
            ]
        },
        {
            "status": "SUPPORTED",
            "id": "v1.0",
            "links": [
                {
                    "href": "%sv1/" % BASE_URL,
                    "rel": "self"
                }
            ]
        }
    ]
}


def _create_version_list(versions):
    return {'versions': {'values': versions}}


def _create_single_version(version):
    return {'version': version}


V3_VERSION_LIST = _create_version_list([V3_VERSION, V2_VERSION])
V2_VERSION_LIST = _create_version_list([V2_VERSION])

V3_VERSION_ENTRY = _create_single_version(V3_VERSION)
V2_VERSION_ENTRY = _create_single_version(V2_VERSION)


class CatalogHackTests(utils.TestCase):

    TEST_URL = 'http://keystone.server:5000/v2.0'
    OTHER_URL = 'http://other.server:5000/path'

    IDENTITY = 'identity'

    BASE_URL = 'http://keystone.server:5000/'
    V2_URL = BASE_URL + 'v2.0'
    V3_URL = BASE_URL + 'v3'

    def setUp(self):
        super(CatalogHackTests, self).setUp()
        self.hacks = discover._VersionHacks()
        self.hacks.add_discover_hack(self.IDENTITY,
                                     re.compile('/v2.0/?$'),
                                     '/')

    def test_version_hacks(self):
        self.assertEqual(self.BASE_URL,
                         self.hacks.get_discover_hack(self.IDENTITY,
                                                      self.V2_URL))

        self.assertEqual(self.BASE_URL,
                         self.hacks.get_discover_hack(self.IDENTITY,
                                                      self.V2_URL + '/'))

        self.assertEqual(self.OTHER_URL,
                         self.hacks.get_discover_hack(self.IDENTITY,
                                                      self.OTHER_URL))

    def test_ignored_non_service_type(self):
        self.assertEqual(self.V2_URL,
                         self.hacks.get_discover_hack('other', self.V2_URL))


class DiscoverUtils(utils.TestCase):

    def test_version_number(self):
        def assertVersion(inp, out):
            self.assertEqual(out, discover.normalize_version_number(inp))

        def versionRaises(inp):
            self.assertRaises(TypeError,
                              discover.normalize_version_number,
                              inp)

        assertVersion('v1.2', (1, 2))
        assertVersion('v11', (11, 0))
        assertVersion('1.2', (1, 2))
        assertVersion('1.5.1', (1, 5, 1))
        assertVersion('1', (1, 0))
        assertVersion(1, (1, 0))
        assertVersion(5.2, (5, 2))
        assertVersion('3.20', (3, 20))
        assertVersion((6, 1), (6, 1))
        assertVersion([1, 4], (1, 4))

        versionRaises('hello')
        versionRaises('1.a')
        versionRaises('vacuum')


class VersionDataTests(utils.TestCase):

    def setUp(self):
        super(VersionDataTests, self).setUp()
        self.session = session.Session()

    def test_version_data_basics(self):
        examples = {'keystone': V3_VERSION_LIST,
                    'cinder': CINDER_EXAMPLES,
                    'glance': GLANCE_EXAMPLES}

        for path, data in examples.items():
            url = "%s%s" % (BASE_URL, path)

            mock = self.requests_mock.get(url, status_code=300, json=data)

            disc = discover.Discover(self.session, url)
            raw_data = disc.raw_version_data()
            clean_data = disc.version_data()

            for v in raw_data:
                for n in ('id', 'status', 'links'):
                    msg = '%s missing from %s version data' % (n, path)
                    self.assertThat(v, matchers.Annotate(msg,
                                                         matchers.Contains(n)))

            for v in clean_data:
                for n in ('version', 'url', 'raw_status'):
                    msg = '%s missing from %s version data' % (n, path)
                    self.assertThat(v, matchers.Annotate(msg,
                                                         matchers.Contains(n)))

            self.assertTrue(mock.called_once)

    def test_version_data_individual(self):
        mock = self.requests_mock.get(V3_URL,
                                      status_code=200,
                                      json=V3_VERSION_ENTRY)

        disc = discover.Discover(self.session, V3_URL)
        raw_data = disc.raw_version_data()
        clean_data = disc.version_data()

        for v in raw_data:
            self.assertEqual(v['id'], 'v3.0')
            self.assertEqual(v['status'], 'stable')
            self.assertIn('media-types', v)
            self.assertIn('links', v)

        for v in clean_data:
            self.assertEqual(v['version'], (3, 0))
            self.assertEqual(v['raw_status'], 'stable')
            self.assertEqual(v['url'], V3_URL)

        self.assertTrue(mock.called_once)

    def test_keystone_version_data(self):
        mock = self.requests_mock.get(BASE_URL,
                                      status_code=300,
                                      json=V3_VERSION_LIST)

        disc = discover.Discover(self.session, BASE_URL)
        raw_data = disc.raw_version_data()
        clean_data = disc.version_data()

        self.assertEqual(2, len(raw_data))
        self.assertEqual(2, len(clean_data))

        for v in raw_data:
            self.assertIn(v['id'], ('v2.0', 'v3.0'))
            self.assertEqual(v['updated'], UPDATED)
            self.assertEqual(v['status'], 'stable')

            if v['id'] == 'v3.0':
                self.assertEqual(v['media-types'], V3_MEDIA_TYPES)

        for v in clean_data:
            self.assertIn(v['version'], ((2, 0), (3, 0)))
            self.assertEqual(v['raw_status'], 'stable')

        version = disc.data_for('v3.0')
        self.assertEqual((3, 0), version['version'])
        self.assertEqual('stable', version['raw_status'])
        self.assertEqual(V3_URL, version['url'])

        version = disc.data_for(2)
        self.assertEqual((2, 0), version['version'])
        self.assertEqual('stable', version['raw_status'])
        self.assertEqual(V2_URL, version['url'])

        self.assertIsNone(disc.url_for('v4'))
        self.assertEqual(V3_URL, disc.url_for('v3'))
        self.assertEqual(V2_URL, disc.url_for('v2'))

        self.assertTrue(mock.called_once)

    def test_cinder_version_data(self):
        mock = self.requests_mock.get(BASE_URL,
                                      status_code=300,
                                      json=CINDER_EXAMPLES)

        disc = discover.Discover(self.session, BASE_URL)
        raw_data = disc.raw_version_data()
        clean_data = disc.version_data()

        self.assertEqual(3, len(raw_data))

        for v in raw_data:
            self.assertEqual(v['status'], 'CURRENT')
            if v['id'] == 'v1.0':
                self.assertEqual(v['updated'], '2012-01-04T11:33:21Z')
            elif v['id'] == 'v2.0':
                self.assertEqual(v['updated'], '2012-11-21T11:33:21Z')
            elif v['id'] == 'v3.0':
                self.assertEqual(v['updated'], '2012-11-21T11:33:21Z')
            else:
                self.fail("Invalid version found")

        v1_url = "%sv1/" % BASE_URL
        v2_url = "%sv2/" % BASE_URL
        v3_url = "%sv3/" % BASE_URL

        self.assertEqual(clean_data, [
            {
                'collection': None,
                'max_microversion': None,
                'min_microversion': None,
                'version': (1, 0),
                'url': v1_url,
                'raw_status': 'CURRENT',
            },
            {
                'collection': None,
                'max_microversion': None,
                'min_microversion': None,
                'version': (2, 0),
                'url': v2_url,
                'raw_status': 'CURRENT',
            },
            {
                'collection': BASE_URL,
                'max_microversion': (3, 27),
                'min_microversion': (3, 0),
                'version': (3, 0),
                'url': v3_url,
                'raw_status': 'CURRENT',
            },
        ])

        version = disc.data_for('v2.0')
        self.assertEqual((2, 0), version['version'])
        self.assertEqual('CURRENT', version['raw_status'])
        self.assertEqual(v2_url, version['url'])

        version = disc.data_for(1)
        self.assertEqual((1, 0), version['version'])
        self.assertEqual('CURRENT', version['raw_status'])
        self.assertEqual(v1_url, version['url'])

        self.assertIsNone(disc.url_for('v4'))
        self.assertEqual(v3_url, disc.url_for('v3'))
        self.assertEqual(v2_url, disc.url_for('v2'))
        self.assertEqual(v1_url, disc.url_for('v1'))

        self.assertTrue(mock.called_once)

    def test_glance_version_data(self):
        mock = self.requests_mock.get(BASE_URL,
                                      status_code=200,
                                      json=GLANCE_EXAMPLES)

        disc = discover.Discover(self.session, BASE_URL)
        raw_data = disc.raw_version_data()
        clean_data = disc.version_data()

        self.assertEqual(5, len(raw_data))

        for v in raw_data:
            if v['id'] in ('v2.2', 'v1.1'):
                self.assertEqual(v['status'], 'CURRENT')
            elif v['id'] in ('v2.1', 'v2.0', 'v1.0'):
                self.assertEqual(v['status'], 'SUPPORTED')
            else:
                self.fail("Invalid version found")

        v1_url = '%sv1/' % BASE_URL
        v2_url = '%sv2/' % BASE_URL

        self.assertEqual(clean_data, [
            {
                'collection': None,
                'max_microversion': None,
                'min_microversion': None,
                'version': (1, 0),
                'url': v1_url,
                'raw_status': 'SUPPORTED',
            },
            {
                'collection': None,
                'max_microversion': None,
                'min_microversion': None,
                'version': (1, 1),
                'url': v1_url,
                'raw_status': 'CURRENT',
            },
            {
                'collection': None,
                'max_microversion': None,
                'min_microversion': None,
                'version': (2, 0),
                'url': v2_url,
                'raw_status': 'SUPPORTED',
            },
            {
                'collection': None,
                'max_microversion': None,
                'min_microversion': None,
                'version': (2, 1),
                'url': v2_url,
                'raw_status': 'SUPPORTED',
            },
            {
                'collection': None,
                'max_microversion': None,
                'min_microversion': None,
                'version': (2, 2),
                'url': v2_url,
                'raw_status': 'CURRENT',
            },
        ])

        for ver in (2, 2.1, 2.2):
            version = disc.data_for(ver)
            self.assertEqual((2, 2), version['version'])
            self.assertEqual('CURRENT', version['raw_status'])
            self.assertEqual(v2_url, version['url'])
            self.assertEqual(v2_url, disc.url_for(ver))

        for ver in (1, 1.1):
            version = disc.data_for(ver)
            self.assertEqual((1, 1), version['version'])
            self.assertEqual('CURRENT', version['raw_status'])
            self.assertEqual(v1_url, version['url'])
            self.assertEqual(v1_url, disc.url_for(ver))

        self.assertIsNone(disc.url_for('v3'))
        self.assertIsNone(disc.url_for('v2.3'))

        self.assertTrue(mock.called_once)

    def test_allow_deprecated(self):
        status = 'deprecated'
        version_list = [{'id': 'v3.0',
                         'links': [{'href': V3_URL, 'rel': 'self'}],
                         'media-types': V3_MEDIA_TYPES,
                         'status': status,
                         'updated': UPDATED}]
        self.requests_mock.get(BASE_URL, json={'versions': version_list})

        disc = discover.Discover(self.session, BASE_URL)

        # deprecated is allowed by default
        versions = disc.version_data(allow_deprecated=False)
        self.assertEqual(0, len(versions))

        versions = disc.version_data(allow_deprecated=True)
        self.assertEqual(1, len(versions))
        self.assertEqual(status, versions[0]['raw_status'])
        self.assertEqual(V3_URL, versions[0]['url'])
        self.assertEqual((3, 0), versions[0]['version'])

    def test_allow_experimental(self):
        status = 'experimental'
        version_list = [{'id': 'v3.0',
                         'links': [{'href': V3_URL, 'rel': 'self'}],
                         'media-types': V3_MEDIA_TYPES,
                         'status': status,
                         'updated': UPDATED}]
        self.requests_mock.get(BASE_URL, json={'versions': version_list})

        disc = discover.Discover(self.session, BASE_URL)

        versions = disc.version_data()
        self.assertEqual(0, len(versions))

        versions = disc.version_data(allow_experimental=True)
        self.assertEqual(1, len(versions))
        self.assertEqual(status, versions[0]['raw_status'])
        self.assertEqual(V3_URL, versions[0]['url'])
        self.assertEqual((3, 0), versions[0]['version'])

    def test_allow_unknown(self):
        status = 'abcdef'
        version_list = fixture.DiscoveryList(BASE_URL,
                                             v2=False,
                                             v3_status=status)
        self.requests_mock.get(BASE_URL, json=version_list)

        disc = discover.Discover(self.session, BASE_URL)

        versions = disc.version_data()
        self.assertEqual(0, len(versions))

        versions = disc.version_data(allow_unknown=True)
        self.assertEqual(1, len(versions))
        self.assertEqual(status, versions[0]['raw_status'])
        self.assertEqual(V3_URL, versions[0]['url'])
        self.assertEqual((3, 0), versions[0]['version'])

    def test_ignoring_invalid_links(self):
        version_list = [{'id': 'v3.0',
                         'links': [{'href': V3_URL, 'rel': 'self'}],
                         'media-types': V3_MEDIA_TYPES,
                         'status': 'stable',
                         'updated': UPDATED},
                        {'id': 'v3.1',
                         'media-types': V3_MEDIA_TYPES,
                         'status': 'stable',
                         'updated': UPDATED},
                        {'media-types': V3_MEDIA_TYPES,
                         'status': 'stable',
                         'updated': UPDATED,
                         'links': [{'href': V3_URL, 'rel': 'self'}],
                         }]

        self.requests_mock.get(BASE_URL, json={'versions': version_list})

        disc = discover.Discover(self.session, BASE_URL)

        # raw_version_data will return all choices, even invalid ones
        versions = disc.raw_version_data()
        self.assertEqual(3, len(versions))

        # only the version with both id and links will be actually returned
        versions = disc.version_data()
        self.assertEqual(1, len(versions))
