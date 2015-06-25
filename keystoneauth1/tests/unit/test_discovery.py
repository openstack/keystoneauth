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

import six

from keystoneauth1 import discover
from keystoneauth1 import fixture
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

V3_TOKEN = six.u('3e2813b7ba0b4006840c3825860b86ed'),
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
    return json.dumps({'versions': {'values': versions}})


def _create_single_version(version):
    return json.dumps({'version': version})


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
        assertVersion((6, 1), (6, 1))
        assertVersion([1, 4], (1, 4))

        versionRaises('hello')
        versionRaises('1.a')
        versionRaises('vacuum')
