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

"""The passive components to version discovery.

The Discover object in discover.py contains functions that can create objects
on your behalf. These functions are not usable from within the keystoneauth1
library because you will get dependency resolution issues.

The Discover object in this file provides the querying components of Discovery.
This includes functions like url_for which allow you to retrieve URLs and the
raw data specified in version discovery responses.
"""

import copy
import re

from positional import positional
import six
from six.moves import urllib

from keystoneauth1 import _utils as utils
from keystoneauth1 import exceptions


_LOGGER = utils.get_logger(__name__)


@positional()
def get_version_data(session, url, authenticated=None):
    """Retrieve raw version data from a url."""
    headers = {'Accept': 'application/json'}

    resp = session.get(url, headers=headers, authenticated=authenticated)

    try:
        body_resp = resp.json()
    except ValueError:
        pass
    else:
        # In the event of querying a root URL we will get back a list of
        # available versions.
        try:
            return body_resp['versions']['values']
        except (KeyError, TypeError):
            pass

        # Most servers don't have a 'values' element so accept a simple
        # versions dict if available.
        try:
            return body_resp['versions']
        except KeyError:
            pass

        # Otherwise if we query an endpoint like /v2.0 then we will get back
        # just the one available version.
        try:
            return [body_resp['version']]
        except KeyError:
            pass

    err_text = resp.text[:50] + '...' if len(resp.text) > 50 else resp.text
    raise exceptions.DiscoveryFailure('Invalid Response - Bad version data '
                                      'returned: %s' % err_text)


def normalize_version_number(version):
    """Turn a version representation into a tuple.

    Examples:

    The following all produce a return value of (1, 0)::

      1, '1', 'v1', [1], (1,), ['1'], 1.0, '1.0', 'v1.0', (1, 0)

    The following all produce a return value of (1, 20, 3)::

      'v1.20.3', '1.20.3', (1, 20, 3), ['1', '20', '3']

    :param version: A version specifier in any of the following forms:
        String, possibly prefixed with 'v', containing one or more numbers
        separated by periods.  Examples: 'v1', 'v1.2', '1.2.3', '123'
        Integer.  This will be assumed to be the major version, with a minor
        version of 0.
        Float.  The integer part is assumed to be the major version; the
        decimal part the minor version.
        Non-string iterable comprising integers or integer strings.
        Examples: (1,), [1, 2], ('12', '34', '56')
    :return: A tuple of integers of len >= 2.
    :rtype: tuple(int)
    :raises TypeError: If the input version cannot be interpreted.
    """
    # Copy the input var so the error presents the original value
    ver = version

    # If it's a non-string iterable, turn it into a string for subsequent
    # processing.  This ensures at least 1 decimal point if e.g. [1] is given.
    if not isinstance(ver, six.string_types):
        try:
            ver = '.'.join(map(str, ver))
        except TypeError:
            # Not an iterable
            pass

    # If it's a numeric or an integer as a string then normalize it to a
    # float string. This ensures 1 decimal point.
    # If it's a float as a string, don't do that, the split/map below will do
    # what we want. (Otherwise, we wind up with 3.20 -> (3, 2))
    if isinstance(ver, six.string_types):
        # trim the v from a 'v2.0' or similar
        ver = ver.lstrip('v')
        try:
            # If version is a pure int, like '1' or '200' this will produce
            # a stringified version with a .0 added. If it's any other number,
            # such as '1.1' - int(version) raises an Exception
            ver = str(float(int(ver)))
        except ValueError:
            pass

    # If it's an int or float, turn it into a float string
    elif isinstance(ver, (int, float)):
        ver = str(float(ver))

    # At this point, we should either have a string that contains numbers with
    # at least one decimal point, or something decidedly else.

    # if it's a string from above break it on .
    try:
        ver = ver.split('.')
    except AttributeError:
        # Not a string
        pass

    # It's either an interable, or something else that makes us sad.
    try:
        return tuple(map(int, ver))
    except (TypeError, ValueError):
        pass

    raise TypeError('Invalid version specified: %s' % version)


def _normalize_version_args(version, min_version, max_version):
    if version and (min_version or max_version):
        raise ValueError(
            "version is mutually exclusive with min_version and"
            " max_version")
    if min_version == 'latest' and max_version not in (
            None, 'latest'):
        raise ValueError(
            "min_version is 'latest' and max_version is {max_version}"
            " but is only allowed to be 'latest' or None".format(
                max_version=max_version))

    if version and version != 'latest':
        version = normalize_version_number(version)

    if min_version:
        if min_version == 'latest':
            min_version = None
            max_version = 'latest'
        else:
            min_version = normalize_version_number(min_version)

    if max_version and max_version != 'latest':
        max_version = normalize_version_number(max_version)

    return version, min_version, max_version


def version_to_string(version):
    """Turn a version tuple into a string."""
    return ".".join([str(x) for x in version])


def version_between(min_version, max_version, candidate):
    # A version can't be between a range that doesn't exist
    if not min_version and not max_version:
        return False

    # If the candidate is less than the min_version, it's
    # not a match.
    if min_version:
        min_version = normalize_version_number(min_version)
        if candidate < min_version:
            return False

    # Lack of max_version implies latest.
    if max_version == 'latest' or not max_version:
        return True

    max_version = normalize_version_number(max_version)
    if version_match(max_version, candidate):
        return True
    if max_version < candidate:
        return False
    return True


def version_match(required, candidate):
    """Test that an available version satisfies the required version.

    To be suitable a version must be of the same major version as required
    and be at least a match in minor/patch level.

    eg. 3.3 is a match for a required 3.1 but 4.1 is not.

    :param tuple required: the version that must be met.
    :param tuple candidate: the version to test against required.

    :returns: True if candidate is suitable False otherwise.
    :rtype: bool
    """
    # major versions must be the same (e.g. even though v2 is a lower
    # version than v3 we can't use it if v2 was requested)
    if candidate[0] != required[0]:
        return False

    # prevent selecting a minor version less than what is required
    if candidate < required:
        return False

    return True


def _combine_relative_url(discovery_url, version_url):
    # NOTE(jamielennox): urllib.parse.urljoin allows the url to be relative
    # or even protocol-less. The additional trailing '/' makes urljoin respect
    # the current path as canonical even if the url doesn't include it. for
    # example a "v2" path from http://host/admin should resolve as
    # http://host/admin/v2 where it would otherwise be host/v2. This has no
    # effect on absolute urls.
    url = urllib.parse.urljoin(discovery_url.rstrip('/') + '/', version_url)

    # Parse and recombine the result to squish double //'s from the above
    return urllib.parse.urlparse(url).geturl()


class Discover(object):

    CURRENT_STATUSES = ('stable', 'current', 'supported')
    DEPRECATED_STATUSES = ('deprecated',)
    EXPERIMENTAL_STATUSES = ('experimental',)

    @positional()
    def __init__(self, session, url, authenticated=None):
        self._url = url
        self._data = get_version_data(session, url,
                                      authenticated=authenticated)

    def raw_version_data(self, allow_experimental=False,
                         allow_deprecated=True, allow_unknown=False):
        """Get raw version information from URL.

        Raw data indicates that only minimal validation processing is performed
        on the data, so what is returned here will be the data in the same
        format it was received from the endpoint.

        :param bool allow_experimental: Allow experimental version endpoints.
        :param bool allow_deprecated: Allow deprecated version endpoints.
        :param bool allow_unknown: Allow endpoints with an unrecognised status.

        :returns: The endpoints returned from the server that match the
                  criteria.
        :rtype: list
        """
        versions = []
        for v in self._data:
            try:
                status = v['status']
            except KeyError:
                _LOGGER.warning('Skipping over invalid version data. '
                                'No stability status in version.')
                continue

            status = status.lower()

            if status in self.CURRENT_STATUSES:
                versions.append(v)
            elif status in self.DEPRECATED_STATUSES:
                if allow_deprecated:
                    versions.append(v)
            elif status in self.EXPERIMENTAL_STATUSES:
                if allow_experimental:
                    versions.append(v)
            elif allow_unknown:
                versions.append(v)

        return versions

    @positional()
    def version_data(self, reverse=False, **kwargs):
        """Get normalized version data.

        Return version data in a structured way.

        :param bool reverse: Reverse the list. reverse=true will mean the
                             returned list is sorted from newest to oldest
                             version.
        :returns: A list of version data dictionaries sorted by version number.
                  Each data element in the returned list is a dictionary
                  consisting of at least:

          :version tuple: The normalized version of the endpoint.
          :url str: The url for the endpoint.
          :raw_status str: The status as provided by the server
        :rtype: list(dict)
        """
        data = self.raw_version_data(**kwargs)
        versions = []

        for v in data:
            try:
                version_str = v['id']
            except KeyError:
                _LOGGER.info('Skipping invalid version data. Missing ID.')
                continue

            try:
                links = v['links']
            except KeyError:
                _LOGGER.info('Skipping invalid version data. Missing links')
                continue

            version_number = normalize_version_number(version_str)

            # collect microversion information
            min_microversion = v.get('min_version') or None
            if min_microversion:
                min_microversion = normalize_version_number(min_microversion)
            max_microversion = v.get('max_version', v.get('version')) or None
            if max_microversion:
                max_microversion = normalize_version_number(max_microversion)

            self_url = None
            collection_url = None
            for link in links:
                try:
                    rel = link['rel']
                    url = _combine_relative_url(self._url, link['href'])
                except (KeyError, TypeError):
                    _LOGGER.info('Skipping invalid version link. '
                                 'Missing link URL or relationship.')
                    continue

                if rel.lower() == 'self':
                    self_url = url
                elif rel.lower() == 'collection':
                    collection_url = url
            if not self_url:
                _LOGGER.info('Skipping invalid version data. '
                             'Missing link to endpoint.')
                continue

            versions.append({'version': version_number,
                             'url': self_url,
                             'collection': collection_url,
                             'min_microversion': min_microversion,
                             'max_microversion': max_microversion,
                             'raw_status': v['status']})

        versions.sort(key=lambda v: v['version'], reverse=reverse)
        return versions

    def data_for(self, version, **kwargs):
        """Return endpoint data for a version.

        NOTE: This method raises a TypeError if version is None. It is
              kept for backwards compatability. New code should use
              versioned_data_for instead.

        :param tuple version: The version is always a minimum version in the
            same major release as there should be no compatibility issues with
            using a version newer than the one asked for.

        :returns: the endpoint data for a URL that matches the required version
                  (the format is described in version_data) or None if no
                  match.
        :rtype: dict
        """
        version = normalize_version_number(version)

        for data in self.version_data(reverse=True, **kwargs):
            if version_match(version, data['version']):
                return data

        return None

    def url_for(self, version, **kwargs):
        """Get the endpoint url for a version.

        NOTE: This method raises a TypeError if version is None. It is
              kept for backwards compatability. New code should use
              versioned_url_for instead.

        :param tuple version: The version is always a minimum version in the
            same major release as there should be no compatibility issues with
            using a version newer than the one asked for.

        :returns: The url for the specified version or None if no match.
        :rtype: str
        """
        data = self.data_for(version, **kwargs)
        return data['url'] if data else None

    def versioned_data_for(self, version=None, url=None,
                           min_version=None, max_version=None,
                           **kwargs):
        """Return endpoint data for the service at a url.

        version, min_version and max_version can all be given either as a
        string or a tuple.

        :param version: The version is the minimum version in the
            same major release as there should be no compatibility issues with
            using a version newer than the one asked for. If version is not
            given, the highest available version will be matched.
        :param string url: If url is given, the data will be returned for the
            endpoint data that has a self link matching the url.
        :param min_version: The minimum version that is acceptable. Mutually
            exclusive with version. If min_version is given with no max_version
            it is as if max version is 'latest'. If min_version is 'latest',
            max_version may only be 'latest' or None.
        :param max_version: The maximum version that is acceptable. Mutually
            exclusive with version. If min_version is given with no max_version
            it is as if max version is 'latest'. If min_version is 'latest',
            max_version may only be 'latest' or None.

        :returns: the endpoint data for a URL that matches the required version
                  (the format is described in version_data) or None if no
                  match.
        :rtype: dict
        """
        version, min_version, max_version = _normalize_version_args(
            version, min_version, max_version)
        no_version = not version and not max_version and not min_version

        version_data = self.version_data(reverse=True, **kwargs)

        # If we don't have to check a min_version, we can short
        # circuit anything else
        if 'latest' in (version, max_version) and not min_version:
            # because we reverse we can just take the first entry
            return version_data[0]

        if url:
            url = url.rstrip('/') + '/'

        if no_version and not url:
            # because we reverse we can just take the first entry
            return version_data[0]

        # Version data is in order from highest to lowest, so we return
        # the first matching entry
        for data in version_data:
            if url and data['url'] and data['url'].rstrip('/') + '/' == url:
                return data
            if version and version_match(version, data['version']):
                return data
            if version_between(min_version, max_version, data['version']):
                return data

        # If there is no version requested and we could not find a matching
        # url in the discovery doc, that means we've got an unversioned
        # endpoint in the catalog and the user is requesting version data
        # so that they know what version they got. We can return the first
        # entry from version_data, because the user hasn't requested anything
        # different.
        if no_version and url:
            return version_data[0]

        # We couldn't find a match.
        return None

    def versioned_url_for(self, version=None,
                          min_version=None, max_version=None, **kwargs):
        """Get the endpoint url for a version.

        version, min_version and max_version can all be given either as a
        string or a tuple.

        :param version: The version is always a minimum version in the
            same major release as there should be no compatibility issues with
            using a version newer than the one asked for.
        :param min_version: The minimum version that is acceptable. Mutually
            exclusive with version. If min_version is given with no max_version
            it is as if max version is 'latest'.
        :param max_version: The maximum version that is acceptable. Mutually
            exclusive with version. If min_version is given with no max_version
            it is as if max version is 'latest'.

        :returns: The url for the specified version or None if no match.
        :rtype: str
        """
        data = self.versioned_data_for(version, min_version=min_version,
                                       max_version=max_version, **kwargs)
        return data['url'] if data else None


class EndpointData(object):
    """Normalized information about a discovered endpoint.

    Contains url, version, microversion, interface and region information.
    This is essentially the data contained in the catalog and the version
    discovery documents about an endpoint that is used to select the endpoint
    desired by the user. It is returned so that a user can know which qualities
    a discovered endpoint had, in case their request allowed for a range of
    possibilities.
    """

    @positional()
    def __init__(self,
                 catalog_url=None,
                 service_url=None,
                 service_type=None,
                 service_name=None,
                 service_id=None,
                 region_name=None,
                 interface=None,
                 endpoint_id=None,
                 raw_endpoint=None,
                 api_version=None,
                 major_version=None,
                 min_microversion=None,
                 max_microversion=None):
        self.catalog_url = catalog_url
        self.service_url = service_url
        self.service_type = service_type
        self.service_name = service_name
        self.service_id = service_id
        self.interface = interface
        self.region_name = region_name
        self.endpoint_id = endpoint_id
        self.raw_endpoint = raw_endpoint
        self.api_version = api_version
        self.major_version = major_version
        self.min_microversion = min_microversion
        self.max_microversion = max_microversion
        self._saved_project_id = None
        self._catalog_matches_version = False
        self._catalog_matches_exactly = False
        self._disc = None

    def __copy__(self):
        """Return a new EndpointData based on this one."""
        new_data = EndpointData(
            catalog_url=self.catalog_url,
            service_url=self.service_url,
            service_type=self.service_type,
            service_name=self.service_name,
            service_id=self.service_id,
            region_name=self.region_name,
            interface=self.interface,
            endpoint_id=self.endpoint_id,
            raw_endpoint=self.raw_endpoint,
            api_version=self.api_version,
            major_version=self.major_version,
            min_microversion=self.min_microversion,
            max_microversion=self.max_microversion)
        # Save cached discovery object - but we don't want to
        # actually provide a constructor argument
        new_data._disc = self._disc
        new_data._saved_project_id = self._saved_project_id
        return new_data

    @property
    def url(self):
        return self.service_url or self.catalog_url

    @positional(3)
    def get_versioned_data(self, session, version=None,
                           authenticated=False, allow=None, cache=None,
                           allow_version_hack=True, project_id=None,
                           discover_versions=True,
                           min_version=None, max_version=None):
        """Run version discovery for the service described.

        Performs Version Discovery and returns a new EndpointData object with
        information found.

        version, min_version and max_version can all be given either as a
        string or a tuple.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session
        :param version: The minimum major version required for this endpoint.
                        Mutually exclusive with min_version and max_version.
        :param string project_id: ID of the currently scoped project. Used for
                                  removing project_id components of URLs from
                                  the catalog. (optional)
        :param dict allow: Extra filters to pass when discovering API
                           versions. (optional)
        :param bool allow_version_hack: Allow keystoneauth to hack up catalog
                                        URLS to support older schemes.
                                        (optional, default True)
        :param dict cache: A dict to be used for caching results in
                           addition to caching them on the Session.
                           (optional)
        :param bool authenticated: Include a token in the discovery call.
                                   (optional) Defaults to False.
        :param bool discover_versions: Whether to get version metadata from
                                       the version discovery document even
                                       if it's not neccessary to fulfill the
                                       major version request. (optional,
                                       defaults to True)
        :param min_version: The minimum version that is acceptable. Mutually
                            exclusive with version. If min_version is given
                            with no max_version it is as if max version is
                            'latest'.
        :param max_version: The maximum version that is acceptable. Mutually
                            exclusive with version. If min_version is given
                            with no max_version it is as if max version is
                            'latest'.

        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.
        """
        version, min_version, max_version = _normalize_version_args(
            version, min_version, max_version)

        if not allow:
            allow = {}

        # This method should always return a new EndpointData
        new_data = copy.copy(self)

        new_data._set_version_info(
            session=session, version=version, authenticated=authenticated,
            allow=allow, cache=cache, allow_version_hack=allow_version_hack,
            project_id=project_id, discover_versions=discover_versions,
            min_version=min_version, max_version=max_version)
        return new_data

    def _set_version_info(self, session, version,
                          authenticated=False, allow=None, cache=None,
                          allow_version_hack=True, project_id=None,
                          discover_versions=False,
                          min_version=None, max_version=None):
        match_url = None

        no_version = not version and not max_version and not min_version
        if no_version and not discover_versions:
            # NOTE(jamielennox): This may not be the best thing to default to
            # but is here for backwards compatibility. It may be worth
            # defaulting to the most recent version.
            return
        elif no_version and discover_versions:
            # We want to run discovery, but we don't want to find different
            # endpoints than what's in the catalog
            allow_version_hack = False
            match_url = self.url

        if project_id:
            self.project_id = project_id
        discovered_data = None
        # Maybe we've run discovery in the past and have a document that can
        # satisfy the request without further work
        if self._disc:
            discovered_data = self._disc.versioned_data_for(
                version, min_version=min_version, max_version=max_version,
                url=match_url, **allow)
        if not discovered_data:
            self._run_discovery(
                session=session, cache=cache,
                version=version, min_version=min_version,
                max_version=max_version,
                match_url=match_url, project_id=project_id,
                allow_version_hack=allow_version_hack, allow=allow,
                discover_versions=discover_versions)
            if not self._disc:
                return
            discovered_data = self._disc.versioned_data_for(
                version, min_version=min_version, max_version=max_version,
                url=match_url, **allow)

        if not discovered_data:
            if version:
                raise exceptions.DiscoveryFailure(
                    "Version {version} requested, but was not found".format(
                        version=version_to_string(version)))
            elif min_version and not max_version:
                raise exceptions.DiscoveryFailure(
                    "Minimum version {min_version} was not found".format(
                        min_version=version_to_string(min_version)))
            elif max_version and not min_version:
                raise exceptions.DiscoveryFailure(
                    "Maximum version {max_version} was not found".format(
                        max_version=version_to_string(max_version)))
            elif min_version and max_version:
                raise exceptions.DiscoveryFailure(
                    "No version found between {min_version}"
                    " and {max_version}".format(
                        min_version=version_to_string(min_version),
                        max_version=version_to_string(max_version)))

        self.min_microversion = discovered_data['min_microversion']
        self.max_microversion = discovered_data['max_microversion']

        # TODO(mordred): these next two things should be done by Discover
        # in versioned_data_for.
        discovered_url = discovered_data['url']

        # NOTE(jamielennox): urljoin allows the url to be relative or even
        # protocol-less. The additional trailing '/' make urljoin respect
        # the current path as canonical even if the url doesn't include it.
        # for example a "v2" path from http://host/admin should resolve as
        # http://host/admin/v2 where it would otherwise be host/v2.
        # This has no effect on absolute urls returned from url_for.
        url = urllib.parse.urljoin(self._disc._url.rstrip('/') + '/',
                                   discovered_url)

        # If we had to pop a project_id from the catalog_url, put it back on
        if self._saved_project_id:
            url = urllib.parse.urljoin(url.rstrip('/') + '/',
                                       self._saved_project_id)
        self.service_url = url

    @positional(1)
    def _run_discovery(self, session, cache, version, min_version,
                       max_version, match_url, project_id,
                       allow_version_hack, allow, discover_versions):
        vers_url = None
        tried = set()

        for vers_url in self._get_discovery_url_choices(
                version=version, project_id=project_id,
                allow_version_hack=allow_version_hack,
                min_version=min_version,
                max_version=max_version):

            if self._catalog_matches_exactly and not discover_versions:
                # The version we started with is correct, and we don't want
                # new data
                return

            if vers_url in tried:
                continue
            tried.update(vers_url)

            try:
                self._disc = get_discovery(
                    session, vers_url,
                    cache=cache,
                    authenticated=False)
                break
            except (exceptions.DiscoveryFailure,
                    exceptions.HttpError,
                    exceptions.ConnectionError):
                continue
        if not self._disc:
            # We couldn't find a version discovery document anywhere.
            if self._catalog_matches_version:
                # But - the version in the catalog is fine.
                self.service_url = self.catalog_url
                return

            # NOTE(jamielennox): The logic here is required for backwards
            # compatibility. By itself it is not ideal.
            if allow_version_hack:
                # NOTE(jamielennox): If we can't contact the server we
                # fall back to just returning the URL from the catalog.  This
                # is backwards compatible behaviour and used when there is no
                # other choice. Realistically if you have provided a version
                # you should be able to rely on that version being returned or
                # the request failing.
                _LOGGER.warning(
                    'Failed to contact the endpoint at %s for '
                    'discovery. Fallback to using that endpoint as '
                    'the base url.', self.url)
                return

            else:
                # NOTE(jamielennox): If you've said no to allow_version_hack
                # and we can't determine the actual URL this is a failure
                # because we are specifying that the deployment must be up to
                # date enough to properly specify a version and keystoneauth
                # can't deliver.
                raise exceptions.DiscoveryFailure(
                    "Version requested but version discovery document was not"
                    " found and allow_version_hack was False")

    def _get_discovery_url_choices(
            self, version=None, project_id=None, allow_version_hack=True,
            min_version=None, max_version=None):
        """Find potential locations for version discovery URLs.

        version, min_version and max_version are already normalized, so will
        either be None, 'latest' or a tuple.
        """
        url = urllib.parse.urlparse(self.url)
        url_parts = url.path.split('/')

        # First, check to see if the catalog url ends with a project id
        # We need to remove it and save it for later if it does
        if project_id and url_parts[-1].endswith(project_id):
            self._saved_project_id = url_parts.pop()
        elif not project_id:
            # Peek to see if -2 is a version. If so, -1 is a project_id,
            # even if we don't know that at this point in the call stack
            try:
                url_version = normalize_version_number(url_parts[-2])
                self._saved_project_id = url_parts.pop()
            except TypeError:
                pass

        catalog_discovery = versioned_discovery = None
        high_match = exact_match = None

        # Next, check to see if the url indicates a version and if that
        # version either matches our version request or is withing the
        # range requested. If so, we can start by trying the given url
        # as it has a high potential for success.
        try:
            url_version = normalize_version_number(url_parts[-1])
            versioned_discovery = urllib.parse.ParseResult(
                url.scheme,
                url.netloc,
                '/'.join(url_parts),
                url.params,
                url.query,
                url.fragment).geturl()
        except TypeError:
            pass
        else:
            is_between = version_between(
                min_version, max_version, url_version)
            exact_match = (version and version != 'latest'
                           and version_match(version, url_version))
            high_match = (is_between and max_version
                          and max_version != 'latest' and version_match(
                              max_version, url_version))

            if exact_match or is_between:
                self._catalog_matches_version = True
                self._catalog_matches_exactly = exact_match
                # The endpoint from the catalog matches the version request
                # We construct a URL minus any project_id, but we don't
                # return it just yet. It's a good option, but unless we
                # have an exact match or match the max requested, we want
                # to try for an unversioned endpoint first.
                catalog_discovery = urllib.parse.ParseResult(
                    url.scheme,
                    url.netloc,
                    '/'.join(url_parts),
                    url.params,
                    url.query,
                    url.fragment).geturl()

            # If we found a viable catalog endpoint and it's
            # an exact match or matches the max, go ahead and give
            # it a go.
            if catalog_discovery and (high_match or exact_match):
                yield catalog_discovery
                catalog_discovery = None

            url_parts.pop()

        if allow_version_hack:
            # If there were projects or versions in the url they are now gone.
            # That means we're left with what should be the unversioned url.
            yield urllib.parse.ParseResult(
                url.scheme,
                url.netloc,
                '/'.join(url_parts),
                url.params,
                url.query,
                url.fragment).geturl()

            # If we have a catalog discovery url, it either means we didn't
            # return it earlier because it wasn't an exact enough match, or
            # that we did and it failed. We don't double-request things when
            # consuming this, so it's safe to return it here in case we didn't
            # already return it.
            if catalog_discovery:
                yield catalog_discovery

            # NOTE(mordred): For backwards compatibility people might have
            # added version hacks using the version hack system. The logic
            # above should handle most cases, so by the time we get here it's
            # most likely to be a no-op
            yield self._get_catalog_discover_hack()
        elif versioned_discovery and self._saved_project_id:
            # We popped a project_id but are either avoiding version hacks
            # or we didn't request a version. That means we still want to fetch
            # the document from the "catalog url" - but the catalog url is has
            # a project_id suffix so is likely not going to work for us. Try
            # fetching from the project-less versioned endpoint.
            yield versioned_discovery

        # As a final fallthrough case, return the actual unmodified url from
        # the catalog.
        yield self.catalog_url

    def _get_catalog_discover_hack(self):
        """Apply the catalog hacks and figure out an unversioned endpoint.

        This function is internal to keystoneauth1.

        :param bool allow_version_hack: Whether or not to allow version hacks
                                        to be applied. (defaults to True)

        :returns: A url that has been transformed by the regex hacks that
                  match the service_type.
        """
        return _VERSION_HACKS.get_discover_hack(self.service_type, self.url)


@positional()
def get_discovery(session, url, cache=None, authenticated=False):
    """Return the discovery object for a URL.

    Check the session and the plugin cache to see if we have already
    performed discovery on the URL and if so return it, otherwise create
    a new discovery object, cache it and return it.

    NOTE: This function is expected to be used by keystoneauth and should not
    be needed by users part of normal usage. A normal user should use
    get_endpoint or get_endpoint_data on `keystoneauth.session.Session` or
    endpoint_filters on `keystoneauth.session.Session` or
    `keystoneauth.session.Session`. However, should the user need to perform
    direct discovery for some reason, this function should be used so that
    the discovery caching is used.

    :param session: A session object to discover with.
    :type session: keystoneauth1.session.Session
    :param str url: The url to lookup.
    :param dict cache:
        A dict to be used for caching results, in addition to caching them
        on the Session. (optional) Defaults to None.
    :param bool authenticated:
        Include a token in the discovery call. (optional) Defaults to None,
        which will use a token if an auth plugin is installed.

    :raises keystoneauth1.exceptions.discovery.DiscoveryFailure:
        if for some reason the lookup fails.
    :raises keystoneauth1.exceptions.http.HttpError:
        An error from an invalid HTTP response.

    :returns: A discovery object with the results of looking up that URL.
    :rtype: :py:class:`keystoneauth1.discover.Discovery`
    """
    # There are between one and three different caches. The user may have
    # passed one in. There is definitely one on the session, and there is
    # one on the auth plugin if the Session has an auth plugin.
    caches = []

    # If a cache was passed in, check it first.
    if cache is not None:
        caches.append(cache)

    # If the session has a cache, check it second, since it could have been
    # provided by the user at Session creation time.
    if hasattr(session, '_discovery_cache'):
        caches.append(session._discovery_cache)

    # Finally check the auth cache associated with the Session.
    if session.auth and hasattr(session.auth, '_discovery_cache'):
        caches.append(session.auth._discovery_cache)

    for cache in caches:
        disc = cache.get(url)

        if disc:
            break
    else:
        disc = Discover(session, url, authenticated=authenticated)

    # Whether we get one from fetching or from cache, set it in the
    # caches. This assures that if we combine sessions and auth plugins
    # that we don't make unnecesary calls.
    if disc:
        for cache in caches:
            cache[url] = disc

    return disc


class _VersionHacks(object):
    """A container to abstract the list of version hacks.

    This could be done as simply a dictionary but is abstracted like this to
    make for easier testing.
    """

    def __init__(self):
        self._discovery_data = {}

    def add_discover_hack(self, service_type, old, new=''):
        """Add a new hack for a service type.

        :param str service_type: The service_type in the catalog.
        :param re.RegexObject old: The pattern to use.
        :param str new: What to replace the pattern with.
        """
        hacks = self._discovery_data.setdefault(service_type, [])
        hacks.append((old, new))

    def get_discover_hack(self, service_type, url):
        """Apply the catalog hacks and figure out an unversioned endpoint.

        :param str service_type: the service_type to look up.
        :param str url: The original url that came from a service_catalog.

        :returns: Either the unversioned url or the one from the catalog
                  to try.
        """
        for old, new in self._discovery_data.get(service_type, []):
            new_string, number_of_subs_made = old.subn(new, url)
            if number_of_subs_made > 0:
                return new_string

        return url


_VERSION_HACKS = _VersionHacks()
_VERSION_HACKS.add_discover_hack('identity', re.compile('/v2.0/?$'), '/')


def add_catalog_discover_hack(service_type, old, new):
    """Add a version removal rule for a particular service.

    Originally deployments of OpenStack would contain a versioned endpoint in
    the catalog for different services. E.g. an identity service might look
    like ``http://localhost:5000/v2.0``. This is a problem when we want to use
    a different version like v3.0 as there is no way to tell where it is
    located. We cannot simply change all service catalogs either so there must
    be a way to handle the older style of catalog.

    This function adds a rule for a given service type that if part of the URL
    matches a given regular expression in *old* then it will be replaced with
    the *new* value. This will replace all instances of old with new. It should
    therefore contain a regex anchor.

    For example the included rule states::

        add_catalog_version_hack('identity', re.compile('/v2.0/?$'), '/')

    so if the catalog retrieves an *identity* URL that ends with /v2.0 or
    /v2.0/ then it should replace it simply with / to fix the user's catalog.

    :param str service_type: The service type as defined in the catalog that
                             the rule will apply to.
    :param re.RegexObject old: The regular expression to search for and replace
                               if found.
    :param str new: The new string to replace the pattern with.
    """
    _VERSION_HACKS.add_discover_hack(service_type, old, new)
