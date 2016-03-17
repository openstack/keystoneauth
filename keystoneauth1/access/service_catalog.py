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

from positional import positional
import six

from keystoneauth1 import exceptions


@six.add_metaclass(abc.ABCMeta)
class ServiceCatalog(object):
    """Helper methods for dealing with a Keystone Service Catalog."""

    def __init__(self, catalog):
        self._catalog = catalog

    def _get_endpoint_region(self, endpoint):
        return endpoint.get('region_id') or endpoint.get('region')

    @property
    def catalog(self):
        """Return the raw service catalog content, mostly useful for debugging.

        Applications should avoid this and use accessor methods instead.
        However, there are times when inspecting the raw catalog can be useful
        for analysis and other reasons.
        """
        return self._catalog

    @abc.abstractmethod
    def is_interface_match(self, endpoint, interface):
        """Helper function to normalize endpoint matching across v2 and v3.

        :returns: True if the provided endpoint matches the required
                  interface otherwise False.
        """

    @staticmethod
    def normalize_interface(self, interface):
        """Handle differences in the way v2 and v3 catalogs specify endpoint.

        Both v2 and v3 must be able to handle the endpoint style of the other.
        For example v2 must be able to handle a 'public' interface and
        v3 must be able to handle a 'publicURL' interface.

        :returns: the endpoint string in the format appropriate for this
                  service catalog.
        """
        return interface

    @positional()
    def get_endpoints(self, service_type=None, interface=None,
                      region_name=None, service_name=None,
                      service_id=None, endpoint_id=None):
        """Fetch and filter endpoints for the specified service(s).

        Returns endpoints for the specified service (or all) containing
        the specified type (or all) and region (or all) and service name.

        If there is no name in the service catalog the service_name check will
        be skipped.  This allows compatibility with services that existed
        before the name was available in the catalog.
        """
        interface = self.normalize_interface(interface)

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

            # NOTE(jamielennox): there is no such thing as a service_id in v2
            # similarly to service_name we'll have to skip this check if it's
            # not available.
            if service_id and 'id' in service and service_id != service['id']:
                continue

            endpoints = sc.setdefault(st, [])

            for endpoint in service.get('endpoints', []):
                if (interface and not
                        self.is_interface_match(endpoint, interface)):
                    continue
                if (region_name and
                        region_name != self._get_endpoint_region(endpoint)):
                    continue
                if (endpoint_id and endpoint_id != endpoint.get('id')):
                    continue
                endpoints.append(endpoint)

        return sc

    def _get_service_endpoints(self, service_type=None, **kwargs):
        sc_endpoints = self.get_endpoints(service_type=service_type, **kwargs)

        if service_type:
            endpoints = sc_endpoints.get(service_type, [])
        else:
            # flatten list of lists
            endpoints = [x
                         for endpoint in six.itervalues(sc_endpoints)
                         for x in endpoint]

        return endpoints

    @abc.abstractmethod
    @positional()
    def get_urls(self, service_type=None, interface='public',
                 region_name=None, service_name=None,
                 service_id=None, endpoint_id=None):
        """Fetch endpoint urls from the service catalog.

        Fetch the endpoints from the service catalog for a particular
        endpoint attribute. If no attribute is given, return the first
        endpoint of the specified type.

        :param string service_type: Service type of the endpoint.
        :param string interface: Type of endpoint.
                                     Possible values: public or publicURL,
                                     internal or internalURL, admin or
                                     adminURL
        :param string region_name: Region of the endpoint.
        :param string service_name: The assigned name of the service.
        :param string service_id: The identifier of a service.
        :param string endpoint_id: The identifier of an endpoint.

        :returns: tuple of urls or None (if no match found)
        """
        raise NotImplementedError()

    @positional()
    def url_for(self, service_type=None, interface='public',
                region_name=None, service_name=None,
                service_id=None, endpoint_id=None):
        """Fetch an endpoint from the service catalog.

        Fetch the specified endpoint from the service catalog for
        a particular endpoint attribute. If no attribute is given, return
        the first endpoint of the specified type.

        Valid interface types: `public` or `publicURL`,
                               `internal` or `internalURL`,
                               `admin` or 'adminURL`

        :param string service_type: Service type of the endpoint.
        :param string interface: Type of endpoint.
        :param string region_name: Region of the endpoint.
        :param string service_name: The assigned name of the service.
        :param string service_id: The identifier of a service.
        :param string endpoint_id: The identifier of an endpoint.
        """
        if not self._catalog:
            raise exceptions.EmptyCatalog('The service catalog is empty.')

        urls = self.get_urls(service_type=service_type,
                             interface=interface,
                             region_name=region_name,
                             service_name=service_name,
                             service_id=service_id,
                             endpoint_id=endpoint_id)

        try:
            return urls[0]
        except Exception:
            pass

        if service_name and region_name:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'named %(service_name)s in %(region_name)s region not '
                   'found' %
                   {'interface': interface,
                    'service_type': service_type, 'service_name': service_name,
                    'region_name': region_name})
        elif service_name:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'named %(service_name)s not found' %
                   {'interface': interface,
                    'service_type': service_type,
                    'service_name': service_name})
        elif region_name:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'in %(region_name)s region not found' %
                   {'interface': interface,
                    'service_type': service_type, 'region_name': region_name})
        else:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'not found' %
                   {'interface': interface,
                    'service_type': service_type})

        raise exceptions.EndpointNotFound(msg)


class ServiceCatalogV2(ServiceCatalog):
    """An object for encapsulating the v2 service catalog.

    The object is created using raw v2 auth token from Keystone.
    """

    @classmethod
    def from_token(cls, token):
        if 'access' not in token:
            raise ValueError('Invalid token format for fetching catalog')

        return cls(token['access'].get('serviceCatalog', {}))

    @staticmethod
    def normalize_interface(interface):
        if interface and 'URL' not in interface:
            interface = interface + 'URL'

        return interface

    def is_interface_match(self, endpoint, interface):
        return interface in endpoint

    @positional()
    def get_urls(self, service_type=None, interface='publicURL',
                 region_name=None, service_name=None,
                 service_id=None, endpoint_id=None):
        interface = self.normalize_interface(interface)

        endpoints = self._get_service_endpoints(service_type=service_type,
                                                interface=interface,
                                                region_name=region_name,
                                                service_name=service_name,
                                                service_id=service_id,
                                                endpoint_id=endpoint_id)

        return tuple([endpoint[interface] for endpoint in endpoints])


class ServiceCatalogV3(ServiceCatalog):
    """An object for encapsulating the v3 service catalog.

    The object is created using raw v3 auth token from Keystone.
    """

    @classmethod
    def from_token(cls, token):
        if 'token' not in token:
            raise ValueError('Invalid token format for fetching catalog')

        return cls(token['token'].get('catalog', {}))

    @staticmethod
    def normalize_interface(interface):
        if interface:
            interface = interface.rstrip('URL')

        return interface

    def is_interface_match(self, endpoint, interface):
        try:
            return interface == endpoint['interface']
        except KeyError:
            return False

    @positional()
    def get_urls(self, service_type=None, interface='publicURL',
                 region_name=None, service_name=None,
                 service_id=None, endpoint_id=None):
        endpoints = self._get_service_endpoints(service_type=service_type,
                                                interface=interface,
                                                region_name=region_name,
                                                service_name=service_name,
                                                service_id=service_id,
                                                endpoint_id=endpoint_id)

        return tuple([endpoint['url'] for endpoint in endpoints])
