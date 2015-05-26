# Copyright 2011 OpenStack Foundation
# Copyright 2011, Piston Cloud Computing, Inc.
# Copyright 2011 Nebula, Inc.
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

import six

from keystoneauth import exceptions
from keystoneauth.i18n import _
from keystoneauth import utils


@six.add_metaclass(abc.ABCMeta)
class ServiceCatalog(object):
    """Helper methods for dealing with a Keystone Service Catalog."""

    def __init__(self, catalog):
        self._catalog = catalog

    def _get_endpoint_region(self, endpoint):
        return endpoint.get('region_id') or endpoint.get('region')

    @abc.abstractmethod
    def _is_endpoint_type_match(self, endpoint, endpoint_type):
        """Helper function to normalize endpoint matching across v2 and v3.

        :returns: True if the provided endpoint matches the required
        endpoint_type otherwise False.
        """

    @abc.abstractmethod
    def _normalize_endpoint_type(self, endpoint_type):
        """Handle differences in the way v2 and v3 catalogs specify endpoint.

        Both v2 and v3 must be able to handle the endpoint style of the other.
        For example v2 must be able to handle a 'public' endpoint_type and
        v3 must be able to handle a 'publicURL' endpoint_type.

        :returns: the endpoint string in the format appropriate for this
                  service catalog.
        """

    def get_endpoints(self, service_type=None, endpoint_type=None,
                      region_name=None, service_name=None):
        """Fetch and filter endpoints for the specified service(s).

        Returns endpoints for the specified service (or all) containing
        the specified type (or all) and region (or all) and service name.

        If there is no name in the service catalog the service_name check will
        be skipped.  This allows compatibility with services that existed
        before the name was available in the catalog.
        """
        endpoint_type = self._normalize_endpoint_type(endpoint_type)

        sc = {}

        for service in (self._catalog or []):
            try:
                st = service['type']
            except KeyError:
                continue

            if service_type and service_type != st:
                continue

            # NOTE(jamielennox): service_name is different. It is not available
            # in API < v3.3. If it is in the catalog then we enforce it, if it
            # is not then we don't because the name could be correct we just
            # don't have that information to check against.
            if service_name:
                try:
                    sn = service['name']
                except KeyError:
                    # assume that we're in v3.0-v3.2 and don't have the name in
                    # the catalog. Skip the check.
                    pass
                else:
                    if service_name != sn:
                        continue

            endpoints = sc.setdefault(st, [])

            for endpoint in service.get('endpoints', []):
                if (endpoint_type and not
                        self._is_endpoint_type_match(endpoint, endpoint_type)):
                    continue
                if (region_name and
                        region_name != self._get_endpoint_region(endpoint)):
                    continue
                endpoints.append(endpoint)

        return sc

    def _get_service_endpoints(self, service_type, endpoint_type,
                               region_name, service_name):
        """Fetch the endpoints of a particular service_type and handle
        the filtering.
        """
        sc_endpoints = self.get_endpoints(service_type=service_type,
                                          endpoint_type=endpoint_type,
                                          region_name=region_name,
                                          service_name=service_name)

        try:
            endpoints = sc_endpoints[service_type]
        except KeyError:
            return

        return endpoints

    @abc.abstractmethod
    @utils.positional()
    def get_urls(self, service_type=None, endpoint_type='public',
                 region_name=None, service_name=None):
        """Fetch endpoint urls from the service catalog.

        Fetch the endpoints from the service catalog for a particular
        endpoint attribute. If no attribute is given, return the first
        endpoint of the specified type.

        :param string service_type: Service type of the endpoint.
        :param string endpoint_type: Type of endpoint.
                                     Possible values: public or publicURL,
                                     internal or internalURL, admin or
                                     adminURL
        :param string region_name: Region of the endpoint.
        :param string service_name: The assigned name of the service.

        :returns: tuple of urls or None (if no match found)
        """
        raise NotImplementedError()

    @utils.positional()
    def url_for(self, service_type=None, endpoint_type='public',
                region_name=None, service_name=None):
        """Fetch an endpoint from the service catalog.

        Fetch the specified endpoint from the service catalog for
        a particular endpoint attribute. If no attribute is given, return
        the first endpoint of the specified type.

        Valid endpoint types: `public` or `publicURL`,
                              `internal` or `internalURL`,
                              `admin` or 'adminURL`

        :param string service_type: Service type of the endpoint.
        :param string endpoint_type: Type of endpoint.
        :param string region_name: Region of the endpoint.
        :param string service_name: The assigned name of the service.

        """
        if not self._catalog:
            raise exceptions.EmptyCatalog(_('The service catalog is empty.'))

        urls = self.get_urls(service_type=service_type,
                             endpoint_type=endpoint_type,
                             region_name=region_name,
                             service_name=service_name)

        try:
            return urls[0]
        except Exception:
            pass

        if service_name and region_name:
            msg = (_('%(endpoint_type)s endpoint for %(service_type)s service '
                     'named %(service_name)s in %(region_name)s region not '
                     'found') %
                   {'endpoint_type': endpoint_type,
                    'service_type': service_type, 'service_name': service_name,
                    'region_name': region_name})
        elif service_name:
            msg = (_('%(endpoint_type)s endpoint for %(service_type)s service '
                     'named %(service_name)s not found') %
                   {'endpoint_type': endpoint_type,
                    'service_type': service_type,
                    'service_name': service_name})
        elif region_name:
            msg = (_('%(endpoint_type)s endpoint for %(service_type)s service '
                     'in %(region_name)s region not found') %
                   {'endpoint_type': endpoint_type,
                    'service_type': service_type, 'region_name': region_name})
        else:
            msg = (_('%(endpoint_type)s endpoint for %(service_type)s service '
                     'not found') %
                   {'endpoint_type': endpoint_type,
                    'service_type': service_type})

        raise exceptions.EndpointNotFound(msg)


class ServiceCatalogV2(ServiceCatalog):
    """An object for encapsulating the service catalog using raw v2 auth token
    from Keystone.
    """

    @classmethod
    def from_token(cls, token):
        if 'access' not in token:
            raise ValueError(_('Invalid token format for fetching catalog'))

        return cls(token['access'].get('serviceCatalog', {}))

    def _normalize_endpoint_type(self, endpoint_type):
        if endpoint_type and 'URL' not in endpoint_type:
            endpoint_type = endpoint_type + 'URL'

        return endpoint_type

    def _is_endpoint_type_match(self, endpoint, endpoint_type):
        return endpoint_type in endpoint

    @utils.positional()
    def get_urls(self, service_type=None, endpoint_type='publicURL',
                 region_name=None, service_name=None):
        endpoint_type = self._normalize_endpoint_type(endpoint_type)
        endpoints = self._get_service_endpoints(service_type=service_type,
                                                endpoint_type=endpoint_type,
                                                region_name=region_name,
                                                service_name=service_name)

        if endpoints:
            return tuple([endpoint[endpoint_type] for endpoint in endpoints])
        else:
            return None


class ServiceCatalogV3(ServiceCatalog):
    """An object for encapsulating the service catalog using raw v3 auth token
    from Keystone.
    """

    @classmethod
    def from_token(cls, token):
        if 'token' not in token:
            raise ValueError(_('Invalid token format for fetching catalog'))

        return cls(token['token'].get('catalog', {}))

    def _normalize_endpoint_type(self, endpoint_type):
        if endpoint_type:
            endpoint_type = endpoint_type.rstrip('URL')

        return endpoint_type

    def _is_endpoint_type_match(self, endpoint, endpoint_type):
        try:
            return endpoint_type == endpoint['interface']
        except KeyError:
            return False

    @utils.positional()
    def get_urls(self, service_type=None, endpoint_type='publicURL',
                 region_name=None, service_name=None):
        endpoints = self._get_service_endpoints(service_type=service_type,
                                                endpoint_type=endpoint_type,
                                                region_name=region_name,
                                                service_name=service_name)

        if endpoints:
            return tuple([endpoint['url'] for endpoint in endpoints])
        else:
            return None
