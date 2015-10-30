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


"""Kerberos authentication plugins.

.. warning::
    This module requires installation of an extra package (`requests_kerberos`)
    not installed by default. Without the extra package an import error will
    occur. The extra package can be installed using::

      $ pip install keystoneauth['kerberos']

"""

import requests_kerberos

from keystoneauth1 import access
from keystoneauth1.identity import v3
from keystoneauth1.identity.v3 import federation


def _requests_auth():
    # NOTE(jamielennox): request_kerberos.OPTIONAL allows the plugin to accept
    # unencrypted error messages where we can't verify the origin of the error
    # because we aren't authenticated.
    return requests_kerberos.HTTPKerberosAuth(
        mutual_authentication=requests_kerberos.OPTIONAL)


class KerberosMethod(v3.AuthMethod):

    _method_parameters = []

    def get_auth_data(self, session, auth, headers, request_kwargs, **kwargs):
        # NOTE(jamielennox): request_kwargs is passed as a kwarg however it is
        # required and always present when called from keystoneclient.
        request_kwargs['requests_auth'] = _requests_auth()
        return 'kerberos', {}


class Kerberos(v3.AuthConstructor):
    _auth_method_class = KerberosMethod


class MappedKerberos(federation.FederationBaseAuth):
    """Authenticate using Kerberos via the keystone federation mechanisms.

    This uses the OS-FEDERATION extension to gain an unscoped token and then
    use the standard keystone auth process to scope that to any given project.
    """

    def get_unscoped_auth_ref(self, session, **kwargs):
        resp = session.get(self.federated_token_url,
                           requests_auth=_requests_auth(),
                           authenticated=False)

        return access.create(body=resp.json(), resp=resp)
