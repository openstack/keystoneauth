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

"""Oauth authentication plugins.

.. warning::
    This module requires installation of an extra package (`oauthlib`)
    not installed by default. Without the extra package an import error will
    occur. The extra package can be installed using::

      $ pip install keystoneauth['oauth1']

"""

import logging

try:
    from oauthlib import oauth1
except ImportError:
    oauth1 = None

from keystoneauth1.identity import v3

__all__ = ('OAuth1Method', 'OAuth1')

LOG = logging.getLogger(__name__)


class OAuth1Method(v3.AuthMethod):
    """OAuth based authentication method.

    :param string consumer_key: Consumer key.
    :param string consumer_secret: Consumer secret.
    :param string access_key: Access token key.
    :param string access_secret: Access token secret.
    """

    consumer_key: str
    consumer_secret: str
    access_key: str
    access_secret: str

    _method_parameters = [
        'consumer_key',
        'consumer_secret',
        'access_key',
        'access_secret',
    ]

    # TODO(stephenfin): Deprecate and remove unused kwargs
    def get_auth_data(self, session, auth, headers, request_kwargs, **kwargs):
        # Add the oauth specific content into the headers
        oauth_client = oauth1.Client(
            self.consumer_key,
            client_secret=self.consumer_secret,
            resource_owner_key=self.access_key,
            resource_owner_secret=self.access_secret,
            signature_method=oauth1.SIGNATURE_HMAC,
        )

        o_url, o_headers, o_body = oauth_client.sign(
            auth.token_url, http_method='POST'
        )
        headers.update(o_headers)

        return 'oauth1', {}

    def get_cache_id_elements(self):
        return {
            f'oauth1_{p}': getattr(self, p) for p in self._method_parameters
        }


class OAuth1(v3.AuthConstructor):
    _auth_method_class = OAuth1Method

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.has_scope_parameters:
            LOG.warning(
                'Scoping parameters such as a project were provided '
                'to the OAuth1 plugin. Because OAuth1 access is '
                'always scoped to a project these will be ignored by '
                'the identity server'
            )
