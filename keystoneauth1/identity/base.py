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

import abc
import base64
import hashlib
import json
import threading

from positional import positional
import six
from six.moves import urllib

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import discover
from keystoneauth1 import exceptions
from keystoneauth1 import plugin

LOG = utils.get_logger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseIdentityPlugin(plugin.BaseAuthPlugin):

    # we count a token as valid (not needing refreshing) if it is valid for at
    # least this many seconds before the token expiry time
    MIN_TOKEN_LIFE_SECONDS = 120

    def __init__(self, auth_url=None, reauthenticate=True):

        super(BaseIdentityPlugin, self).__init__()

        self.auth_url = auth_url
        self.auth_ref = None
        self.reauthenticate = reauthenticate

        self._endpoint_cache = {}
        self._lock = threading.Lock()

    @abc.abstractmethod
    def get_auth_ref(self, session, **kwargs):
        """Obtain a token from an OpenStack Identity Service.

        This method is overridden by the various token version plugins.

        This function should not be called independently and is expected to be
        invoked via the do_authenticate function.

        This function will be invoked if the AcessInfo object cached by the
        plugin is not valid. Thus plugins should always fetch a new AccessInfo
        when invoked. If you are looking to just retrieve the current auth
        data then you should use get_access.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.response.InvalidResponse:
            The response returned wasn't appropriate.
        :raises keystoneauth1.exceptions.http.HttpError:
            An error from an invalid HTTP response.

        :returns: Token access information.
        :rtype: :class:`keystoneauth1.access.AccessInfo`
        """

    def get_token(self, session, **kwargs):
        """Return a valid auth token.

        If a valid token is not present then a new one will be fetched.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.

        :return: A valid token.
        :rtype: string
        """
        return self.get_access(session).auth_token

    def _needs_reauthenticate(self):
        """Return if the existing token needs to be re-authenticated.

        The token should be refreshed if it is about to expire.

        :returns: True if the plugin should fetch a new token. False otherwise.
        """
        if not self.auth_ref:
            # authentication was never fetched.
            return True

        if not self.reauthenticate:
            # don't re-authenticate if it has been disallowed.
            return False

        if self.auth_ref.will_expire_soon(self.MIN_TOKEN_LIFE_SECONDS):
            # if it's about to expire we should re-authenticate now.
            return True

        # otherwise it's fine and use the existing one.
        return False

    def get_access(self, session, **kwargs):
        """Fetch or return a current AccessInfo object.

        If a valid AccessInfo is present then it is returned otherwise a new
        one will be fetched.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.

        :returns: Valid AccessInfo
        :rtype: :class:`keystoneauth1.access.AccessInfo`
        """
        # Hey Kids! Thread safety is important particularly in the case where
        # a service is creating an admin style plugin that will then proceed
        # to make calls from many threads. As a token expires all the threads
        # will try and fetch a new token at once, so we want to ensure that
        # only one thread tries to actually fetch from keystone at once.
        with self._lock:
            if self._needs_reauthenticate():
                self.auth_ref = self.get_auth_ref(session)

        return self.auth_ref

    def invalidate(self):
        """Invalidate the current authentication data.

        This should result in fetching a new token on next call.

        A plugin may be invalidated if an Unauthorized HTTP response is
        returned to indicate that the token may have been revoked or is
        otherwise now invalid.

        :returns: True if there was something that the plugin did to
                  invalidate. This means that it makes sense to try again. If
                  nothing happens returns False to indicate give up.
        :rtype: bool
        """
        if self.auth_ref:
            self.auth_ref = None
            return True

        return False

    def get_endpoint(self, session, service_type=None, interface=None,
                     region_name=None, service_name=None, version=None,
                     allow={}, **kwargs):
        """Return a valid endpoint for a service.

        If a valid token is not present then a new one will be fetched using
        the session and kwargs.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session
        :param string service_type: The type of service to lookup the endpoint
                                    for. This plugin will return None (failure)
                                    if service_type is not provided.
        :param string interface: The exposure of the endpoint. Should be
                                 `public`, `internal`, `admin`, or `auth`.
                                 `auth` is special here to use the `auth_url`
                                 rather than a URL extracted from the service
                                 catalog. Defaults to `public`.
        :param string region_name: The region the endpoint should exist in.
                                   (optional)
        :param string service_name: The name of the service in the catalog.
                                   (optional)
        :param tuple version: The minimum version number required for this
                              endpoint. (optional)
        :param dict allow: Extra filters to pass when discovering API
                           versions. (optional)

        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.

        :return: A valid endpoint URL or None if not available.
        :rtype: string or None
        """
        # NOTE(jamielennox): if you specifically ask for requests to be sent to
        # the auth url then we can ignore many of the checks. Typically if you
        # are asking for the auth endpoint it means that there is no catalog to
        # query however we still need to support asking for a specific version
        # of the auth_url for generic plugins.
        if interface is plugin.AUTH_INTERFACE:
            url = self.auth_url
            service_type = service_type or 'identity'

        else:
            if not service_type:
                LOG.warning('Plugin cannot return an endpoint without '
                            'knowing the service type that is required. Add '
                            'service_type to endpoint filtering data.')
                return None

            if not interface:
                interface = 'public'

            service_catalog = self.get_access(session).service_catalog
            url = service_catalog.url_for(service_type=service_type,
                                          interface=interface,
                                          region_name=region_name,
                                          service_name=service_name)

        if not version:
            # NOTE(jamielennox): This may not be the best thing to default to
            # but is here for backwards compatibility. It may be worth
            # defaulting to the most recent version.
            return url

        # NOTE(jamielennox): For backwards compatibility people might have a
        # versioned endpoint in their catalog even though they want to use
        # other endpoint versions. So we support a list of client defined
        # situations where we can strip the version component from a URL before
        # doing discovery.
        hacked_url = discover._get_catalog_discover_hack(service_type, url)

        try:
            disc = self.get_discovery(session, hacked_url, authenticated=False)
        except (exceptions.DiscoveryFailure,
                exceptions.HttpError,
                exceptions.ConnectionError):
            # NOTE(jamielennox): Again if we can't contact the server we fall
            # back to just returning the URL from the catalog. This may not be
            # the best default but we need it for now.
            LOG.warning('Failed to contact the endpoint at %s for discovery. '
                        'Fallback to using that endpoint as the base url.',
                        url)
        else:
            # NOTE(jamielennox): urljoin allows the url to be relative or even
            # protocol-less. The additional trailing '/' make urljoin respect
            # the current path as canonical even if the url doesn't include it.
            # for example a "v2" path from http://host/admin should resolve as
            # http://host/admin/v2 where it would otherwise be host/v2.
            # This has no effect on absolute urls returned from url_for.
            url = disc.url_for(version, **allow)

            if url:
                url = urllib.parse.urljoin(hacked_url.rstrip('/') + '/', url)

        return url

    def get_user_id(self, session, **kwargs):
        return self.get_access(session).user_id

    def get_project_id(self, session, **kwargs):
        return self.get_access(session).project_id

    def get_sp_auth_url(self, session, sp_id, **kwargs):
        try:
            return self.get_access(
                session).service_providers.get_auth_url(sp_id)
        except exceptions.ServiceProviderNotFound:
            return None

    def get_sp_url(self, session, sp_id, **kwargs):
        try:
            return self.get_access(
                session).service_providers.get_sp_url(sp_id)
        except exceptions.ServiceProviderNotFound:
            return None

    @positional()
    def get_discovery(self, session, url, authenticated=None):
        """Return the discovery object for a URL.

        Check the session and the plugin cache to see if we have already
        performed discovery on the URL and if so return it, otherwise create
        a new discovery object, cache it and return it.

        This function is expected to be used by subclasses and should not
        be needed by users.

        :param session: A session object to discover with.
        :type session: keystoneauth1.session.Session
        :param str url: The url to lookup.
        :param bool authenticated: Include a token in the discovery call.
                                   (optional) Defaults to None (use a token
                                   if a plugin is installed).

        :raises keystoneauth1.exceptions.discovery.DiscoveryFailure:
            if for some reason the lookup fails.
        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.

        :returns: A discovery object with the results of looking up that URL.
        """
        # NOTE(jamielennox): we want to cache endpoints on the session as well
        # so that they maintain sharing between auth plugins. Create a cache on
        # the session if it doesn't exist already.
        try:
            session_endpoint_cache = session._identity_endpoint_cache
        except AttributeError:
            session_endpoint_cache = session._identity_endpoint_cache = {}

        # NOTE(jamielennox): There is a cache located on both the session
        # object and the auth plugin object so that they can be shared and the
        # cache is still usable
        for cache in (self._endpoint_cache, session_endpoint_cache):
            disc = cache.get(url)

            if disc:
                break
        else:
            disc = discover.Discover(session, url,
                                     authenticated=authenticated)
            self._endpoint_cache[url] = disc
            session_endpoint_cache[url] = disc

        return disc

    def get_cache_id_elements(self):
        """Get the elements for this auth plugin that make it unique.

        As part of the get_cache_id requirement we need to determine what
        aspects of this plugin and its values that make up the unique elements.

        This should be overridden by plugins that wish to allow caching.

        :returns: The unique attributes and values of this plugin.
        :rtype: A flat dict with a str key and str or None value. This is
                required as we feed these values into a hash. Pairs where the
                value is None are ignored in the hashed id.
        """
        raise NotImplementedError()

    def get_cache_id(self):
        """Fetch an identifier that uniquely identifies the auth options.

        The returned identifier need not be decomposable or otherwise provide
        any way to recreate the plugin.

        This string MUST change if any of the parameters that are used to
        uniquely identity this plugin change. It should not change upon a
        reauthentication of the plugin.

        :returns: A unique string for the set of options
        :rtype: str or None if this is unsupported or unavailable.
        """
        try:
            elements = self.get_cache_id_elements()
        except NotImplementedError:
            return None

        hasher = hashlib.sha256()

        for k, v in sorted(six.iteritems(elements)):
            if v is not None:
                # NOTE(jamielennox): in python3 you need to pass bytes to hash
                if isinstance(k, six.string_types):
                    k = k.encode('utf-8')
                if isinstance(v, six.string_types):
                    v = v.encode('utf-8')

                hasher.update(k)
                hasher.update(v)

        return base64.b64encode(hasher.digest()).decode('utf-8')

    def get_auth_state(self):
        """Retrieve the current authentication state for the plugin.

        Retrieve any internal state that represents the authenticated plugin.

        This should not fetch any new data if it is not present.

        :returns: a string that can be stored or None if there is no auth state
                  present in the plugin. This string can be reloaded with
                  set_auth_state to set the same authentication.
        :rtype: str or None if no auth present.
        """
        if self.auth_ref:
            data = {'auth_token': self.auth_ref.auth_token,
                    'body': self.auth_ref._data}

            return json.dumps(data)

    def set_auth_state(self, data):
        """Install existing authentication state for a plugin.

        Take the output of get_auth_state and install that authentication state
        into the current authentication plugin.
        """
        if data:
            auth_data = json.loads(data)
            self.auth_ref = access.create(body=auth_data['body'],
                                          auth_token=auth_data['auth_token'])
        else:
            self.auth_ref = None
