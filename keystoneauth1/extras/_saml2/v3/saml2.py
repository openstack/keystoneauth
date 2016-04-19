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

from lxml import etree

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.extras._saml2.v3 import base


class Password(base.BaseSAMLPlugin):
    r"""Implement authentication plugin for SAML2 protocol.

    ECP stands for `Enhanced Client or Proxy` and is a SAML2 extension
    for federated authentication where a transportation layer consists of
    HTTP protocol and XML SOAP messages.

    `Read for more information
    <https://wiki.shibboleth.net/confluence/display/SHIB2/ECP>`_ on ECP.

    Reference the `SAML2 ECP specification <https://www.oasis-open.org/\
    committees/download.php/49979/saml-ecp-v2.0-wd09.pdf>`_.

    Currently only HTTPBasicAuth mechanism is available for the IdP
    authenication.

    :param auth_url: URL of the Identity Service
    :type auth_url: string

    :param identity_provider: name of the Identity Provider the client will
                              authenticate against. This parameter will be used
                              to build a dynamic URL used to obtain unscoped
                              OpenStack token.
    :type identity_provider: string

    :param identity_provider_url: An Identity Provider URL, where the SAML2
                                  authn request will be sent.
    :type identity_provider_url: string

    :param username: User's login
    :type username: string

    :param password: User's password
    :type password: string


    :param protocol: Protocol to be used for the authentication.
                     The name must be equal to one configured at the
                     keystone sp side. This value is used for building
                     dynamic authentication URL.
                     Typical value  would be: saml2
    :type protocol: string

    """

    SAML2_HEADER_INDEX = 0
    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
                 'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_SP_SAML2_REQUEST_HEADERS = {
        'Content-Type': 'application/vnd.paos+xml'
    }

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
    }

    ECP_RELAY_STATE = '//ecp:RelayState'

    ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                                         '@responseConsumerURL')

    ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                            '@AssertionConsumerServiceURL')

    SOAP_FAULT = """
    <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
       <S:Body>
         <S:Fault>
            <faultcode>S:Server</faultcode>
            <faultstring>responseConsumerURL from SP and
            assertionConsumerServiceURL from IdP do not match
            </faultstring>
         </S:Fault>
       </S:Body>
    </S:Envelope>
    """

    def _handle_http_ecp_redirect(self, session, response, method, **kwargs):
        if response.status_code not in (self.HTTP_MOVED_TEMPORARILY,
                                        self.HTTP_SEE_OTHER):
            return response

        location = response.headers['location']
        return session.request(location, method, authenticated=False,
                               **kwargs)

    def _prepare_idp_saml2_request(self, saml2_authn_request):
        header = saml2_authn_request[self.SAML2_HEADER_INDEX]
        saml2_authn_request.remove(header)

    def _check_consumer_urls(self, session, sp_response_consumer_url,
                             idp_sp_response_consumer_url):
        """Check if consumer URLs issued by SP and IdP are equal.

        In the initial SAML2 authn Request issued by a Service Provider
        there is a url called ``consumer url``. A trusted Identity Provider
        should issue identical url. If the URLs are not equal the federated
        authn process should be interrupted and the user should be warned.

        :param session: session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session
        :param sp_response_consumer_url: consumer URL issued by a SP
        :type  sp_response_consumer_url: string
        :param idp_sp_response_consumer_url: consumer URL issued by an IdP
        :type idp_sp_response_consumer_url: string

        """
        if sp_response_consumer_url != idp_sp_response_consumer_url:
            # send fault message to the SP, discard the response
            session.post(sp_response_consumer_url, data=self.SOAP_FAULT,
                         headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
                         authenticated=False)

            # prepare error message and raise an exception.
            msg = ('Consumer URLs from Service Provider %(service_provider)s '
                   '%(sp_consumer_url)s and Identity Provider '
                   '%(identity_provider)s %(idp_consumer_url)s are not equal')
            msg = msg % {
                'service_provider': self.federated_token_url,
                'sp_consumer_url': sp_response_consumer_url,
                'identity_provider': self.identity_provider,
                'idp_consumer_url': idp_sp_response_consumer_url
            }

            raise exceptions.AuthorizationFailure(msg)

    def _send_service_provider_request(self, session):
        """Initial HTTP GET request to the SAML2 protected endpoint.

        It's crucial to include HTTP headers indicating that the client is
        willing to take advantage of the ECP SAML2 extension and receive data
        as the SOAP.
        Unlike standard authentication methods in the OpenStack Identity,
        the client accesses::
        ``/v3/OS-FEDERATION/identity_providers/{identity_providers}/
        protocols/{protocol}/auth``

        After a successful HTTP call the HTTP response should include SAML2
        authn request in the XML format.

        If a HTTP response contains ``X-Subject-Token`` in the headers and
        the response body is a valid JSON assume the user was already
        authenticated and Keystone returned a valid unscoped token.
        Return True indicating the user was already authenticated.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        """
        sp_response = session.get(self.federated_token_url,
                                  headers=self.ECP_SP_EMPTY_REQUEST_HEADERS,
                                  authenticated=False)

        if 'X-Subject-Token' in sp_response.headers:
            self.authenticated_response = sp_response
            return True

        try:
            self.saml2_authn_request = etree.XML(sp_response.content)
        except etree.XMLSyntaxError as e:
            msg = ('SAML2: Error parsing XML returned '
                   'from Service Provider, reason: %s') % e
            raise exceptions.AuthorizationFailure(msg)

        relay_state = self.saml2_authn_request.xpath(
            self.ECP_RELAY_STATE, namespaces=self.ECP_SAML2_NAMESPACES)
        self.relay_state = self._first(relay_state)

        sp_response_consumer_url = self.saml2_authn_request.xpath(
            self.ECP_SERVICE_PROVIDER_CONSUMER_URL,
            namespaces=self.ECP_SAML2_NAMESPACES)
        self.sp_response_consumer_url = self._first(sp_response_consumer_url)
        return False

    def _send_idp_saml2_authn_request(self, session):
        """Present modified SAML2 authn assertion from the Service Provider."""
        self._prepare_idp_saml2_request(self.saml2_authn_request)
        idp_saml2_authn_request = self.saml2_authn_request

        # Currently HTTPBasicAuth method is hardcoded into the plugin
        idp_response = session.post(
            self.identity_provider_url,
            headers={'Content-type': 'text/xml'},
            data=etree.tostring(idp_saml2_authn_request),
            requests_auth=(self.username, self.password),
            authenticated=False, log=False)

        try:
            self.saml2_idp_authn_response = etree.XML(idp_response.content)
        except etree.XMLSyntaxError as e:
            msg = ('SAML2: Error parsing XML returned '
                   'from Identity Provider, reason: %s') % e
            raise exceptions.AuthorizationFailure(msg)

        idp_response_consumer_url = self.saml2_idp_authn_response.xpath(
            self.ECP_IDP_CONSUMER_URL,
            namespaces=self.ECP_SAML2_NAMESPACES)

        self.idp_response_consumer_url = self._first(idp_response_consumer_url)

        self._check_consumer_urls(session, self.idp_response_consumer_url,
                                  self.sp_response_consumer_url)

    def _send_service_provider_saml2_authn_response(self, session):
        """Present SAML2 assertion to the Service Provider.

        The assertion is issued by a trusted Identity Provider for the
        authenticated user. This function directs the HTTP request to SP
        managed URL, for instance: ``https://<host>:<port>/Shibboleth.sso/
        SAML2/ECP``.
        Upon success the there's a session created and access to the protected
        resource is granted. Many implementations of the SP return HTTP 302
        status code pointing to the protected URL (``https://<host>:<port>/v3/
        OS-FEDERATION/identity_providers/{identity_provider}/protocols/
        {protocol_id}/auth`` in this case). Saml2 plugin should point to that
        URL again, with HTTP GET method, expecting an unscoped token.

        :param session: a session object to send out HTTP requests.

        """
        self.saml2_idp_authn_response[0][0] = self.relay_state

        response = session.post(
            self.idp_response_consumer_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
            data=etree.tostring(self.saml2_idp_authn_response),
            authenticated=False, redirect=False)

        # Don't follow HTTP specs - after the HTTP 302/303 response don't
        # repeat the call directed to the Location URL. In this case, this is
        # an indication that saml2 session is now active and protected resource
        # can be accessed.
        response = self._handle_http_ecp_redirect(
            session, response, method='GET',
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS)

        self.authenticated_response = response

    def get_unscoped_auth_ref(self, session):
        """Get unscoped OpenStack token after federated authentication.

        This is a multi-step process including multiple HTTP requests.

        The federated authentication consists of:

        * HTTP GET request to the Identity Service (acting as a Service
          Provider).

          It's crucial to include HTTP headers indicating we are expecting SOAP
          message in return. Service Provider should respond with such SOAP
          message.  This step is handed by a method
          ``Saml2Password_send_service_provider_request()``.

        * HTTP POST request to the external Identity Provider service with
          ECP extension enabled. The content sent is a header removed SOAP
          message  returned from the Service Provider. It's also worth noting
          that ECP extension to the SAML2 doesn't define authentication method.
          The most popular is HttpBasicAuth with just user and password.
          Other possibilities could be X509 certificates or Kerberos.
          Upon successful authentication the user should receive a SAML2
          assertion.
          This step is handed by a method
          ``Saml2Password_send_idp_saml2_authn_request(session)``

        * HTTP POST request again to the Service Provider. The body of the
          request includes SAML2 assertion issued by a trusted Identity
          Provider. The request should be sent to the Service Provider
          consumer url specified in the SAML2 assertion.
          Providing the authentication was successful and both Service Provider
          and Identity Providers are trusted to each other, the Service
          Provider will issue an unscoped token with a list of groups the
          federated user is a member of.
          This step is handed by a method
          ``Saml2Password_send_service_provider_saml2_authn_response()``

          Unscoped token example::

            {
                "token": {
                    "methods": [
                        "saml2"
                    ],
                    "user": {
                        "id": "username%40example.com",
                        "name": "username@example.com",
                        "OS-FEDERATION": {
                            "identity_provider": "ACME",
                            "protocol": "saml2",
                            "groups": [
                                {"id": "abc123"},
                                {"id": "bcd234"}
                            ]
                        }
                    }
                }
            }


        :param session : a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: AccessInfo
        :rtype: :py:class:`keystoneauth1.access.AccessInfo`
        """
        saml_authenticated = self._send_service_provider_request(session)
        if not saml_authenticated:
            self._send_idp_saml2_authn_request(session)
            self._send_service_provider_saml2_authn_response(session)

        return access.create(resp=self.authenticated_response)
