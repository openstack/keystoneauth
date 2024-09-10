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
import typing as ty

try:
    # explicitly re-export symbol
    # https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
    from oauthlib import oauth1 as oauth1
except ImportError:
    oauth1 = None

from keystoneauth1.identity import v3
from keystoneauth1 import session as ks_session

__all__ = ('OAuth1Method', 'OAuth1')

LOG = logging.getLogger(__name__)


class OAuth1Method(v3.AuthMethod):
    """OAuth based authentication method.

    :param string access_key: Access token key.
    :param string access_secret: Access token secret.
    :param string consumer_key: Consumer key.
    :param string consumer_secret: Consumer secret.
    """

    access_key: str
    access_secret: str
    consumer_key: str
    consumer_secret: str

    def __init__(
        self,
        *,
        access_key: str,
        access_secret: str,
        consumer_key: str,
        consumer_secret: str,
    ) -> None:
        self.access_key = access_key
        self.access_secret = access_secret
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

    def get_auth_data(
        self,
        session: ks_session.Session,
        auth: v3.Auth,
        headers: dict[str, str],
        request_kwargs: dict[str, object],
    ) -> ty.Union[tuple[None, None], tuple[str, ty.Mapping[str, object]]]:
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

    def get_cache_id_elements(self) -> dict[str, ty.Optional[str]]:
        return {
            'oauth1_access_key': self.access_key,
            'oauth1_access_secret': self.access_secret,
            'oauth1_consumer_key': self.consumer_key,
            'oauth1_consumer_secret': self.consumer_secret,
        }


class OAuth1(v3.Auth):
    _auth_method_class = OAuth1Method

    def __init__(
        self,
        auth_url: str,
        consumer_key: str,
        consumer_secret: str,
        access_key: str,
        access_secret: str,
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
    ) -> None:
        method = self._auth_method_class(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            access_key=access_key,
            access_secret=access_secret,
        )
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

        if self.has_scope_parameters:
            LOG.warning(
                'Scoping parameters such as a project were provided '
                'to the OAuth1 plugin. Because OAuth1 access is '
                'always scoped to a project these will be ignored by '
                'the identity server'
            )
