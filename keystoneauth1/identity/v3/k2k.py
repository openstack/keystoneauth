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

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import base
from keystoneauth1.identity.v3 import token
from keystoneauth1 import plugin

__all__ = ['Keystone2Keystone']


class Keystone2Keystone(base.BaseAuth):
    """Plugin to execute the keystone to keyestone authentication flow.

    In this plugin, an ECP wrapped SAML assertion provided by a keystone
    Identity Provider (IdP) is used to request an OpenStack unscoped token
    from a keystone Service Provider (SP).

    :param base_plugin: Auth plugin already authenticated against the keystone
                        IdP.
    :type base_plugin: ``keystoneauth1.v3.base.BaseAuth``

    :param service_provider: The Service Provider ID.
    :type service_provider: string

    """

    HTTP_MOVED_TEMPORARILY = 302
    REQUEST_ECP_URL = '/auth/OS-FEDERATION/saml2/ecp'

    rescoping_plugin = token.Token

    def __init__(self, base_plugin, service_provider, **kwargs):
        super(Keystone2Keystone, self).__init__(auth_url=None, **kwargs)

        self._local_cloud_plugin = base_plugin
        self._sp_id = service_provider

    @classmethod
    def _remote_auth_url(cls, auth_url):
        """Return auth_url of the remote OpenStack cloud.

        Remote cloud's auth_url is an endpoint for getting federated unscoped
        token, typically that would be
        ``https://remote.example.com:5000/v3/OS-FEDERATION/identity_providers/
        <idp>/protocols/<proto>/auth``. However we need to generate a real
        auth_url, used for token scoping.  This function assumes there are
        static values today in the remote auth_url stored in the Service
        Provider attribute and those can be used as a delimiter. If the
        sp_auth_url doesn't comply with standard federation auth url the
        function will simply return whole string.

        :param auth_url: auth_url of the remote cloud
        :type auth_url: string

        :returns: auth_url of remote cloud where a token can be validated or
                  scoped.
        :rtype: string

        """
        PATTERN = '/OS-FEDERATION/'
        idx = auth_url.index(PATTERN) if PATTERN in auth_url else len(auth_url)
        return auth_url[:idx]

    def _get_scoping_data(self):
        return {'trust_id': self.trust_id,
                'domain_id': self.domain_id,
                'domain_name': self.domain_name,
                'project_id': self.project_id,
                'project_name': self.project_name,
                'project_domain_id': self.project_domain_id,
                'project_domain_name': self.project_domain_name}

    def _ecp_assertion_request(self, session):
        token_id = self._local_cloud_plugin.get_access(session).auth_token
        body = {
            'auth': {
                'identity': {
                    'methods': ['token'],
                    'token': {
                        'id': token_id
                    }
                },
                'scope': {
                    'service_provider': {
                        'id': self._sp_id
                    }
                }
            }
        }

        return body

    def _get_ecp_assertion(self, session):
        url = self._local_cloud_plugin.get_endpoint(
            session, interface=plugin.AUTH_INTERFACE)
        body = self._ecp_assertion_request(session)

        resp = session.post(url=url + self.REQUEST_ECP_URL, json=body,
                            raise_exc=False)

        # NOTE(marek-denis): I am not sure whether disablig exceptions in the
        # Session object and testing if resp.ok is sufficient. An alternative
        # would be catching locally all exceptions and reraising with custom
        # warning.
        if not resp.ok:
            msg = ("Error while requesting ECP wrapped assertion: response "
                   "exit code: %(status_code)d, reason: %(err)s")
            msg = msg % {'status_code': resp.status_code, 'err': resp.reason}
            raise exceptions.AuthorizationFailure(msg)

        if not resp.text:
            raise exceptions.InvalidResponse(resp)

        return str(resp.text)

    def _send_service_provider_ecp_authn_response(self, session, sp_url,
                                                  sp_auth_url):
        """Present ECP wrapped SAML assertion to the keystone SP.

        The assertion is issued by the keystone IdP and it is targeted to the
        keystone that will serve as Service Provider.

        :param session: a session object to send out HTTP requests.

        :param sp_url: URL where the ECP wrapped SAML assertion will be
                       presented to the keystone SP. Usually, something like:
                       https://sp.com/Shibboleth.sso/SAML2/ECP
        :type sp_url: string

        :param sp_auth_url: Federated authentication URL of the keystone SP.
                            It is specified by IdP, for example:
                            https://sp.com/v3/OS-FEDERATION/identity_providers/
                            idp_id/protocols/protocol_id/auth
        :type sp_auth_url: string

        """

        response = session.post(
            sp_url,
            headers={'Content-Type': 'application/vnd.paos+xml'},
            data=self._get_ecp_assertion(session),
            authenticated=False,
            redirect=False)

        # Don't follow HTTP specs - after the HTTP 302 response don't repeat
        # the call directed to the Location URL. In this case, this is an
        # indication that SAML2 session is now active and protected resource
        # can be accessed.
        if response.status_code == self.HTTP_MOVED_TEMPORARILY:
            response = session.get(
                sp_auth_url,
                headers={'Content-Type': 'application/vnd.paos+xml'},
                authenticated=False)

        return response

    def get_unscoped_auth_ref(self, session, **kwargs):
        sp_auth_url = self._local_cloud_plugin.get_sp_auth_url(
            session, self._sp_id)
        sp_url = self._local_cloud_plugin.get_sp_url(session, self._sp_id)
        self.auth_url = self._remote_auth_url(sp_auth_url)

        response = self._send_service_provider_ecp_authn_response(
            session, sp_url, sp_auth_url)
        return access.create(resp=response)

    def get_auth_ref(self, session, **kwargs):

        auth_ref = self.get_unscoped_auth_ref(session, **kwargs)
        scoping = self._get_scoping_data()
        if any(scoping.values()):
            token_plugin = self.rescoping_plugin(self.auth_url,
                                                 token=auth_ref.auth_token,
                                                 **scoping)
            auth_ref = token_plugin.get_auth_ref(session)
        return auth_ref
