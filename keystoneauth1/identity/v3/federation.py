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

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import base
from keystoneauth1.identity.v3 import token
from keystoneauth1 import session as ks_session

LOG = utils.get_logger(__name__)

__all__ = ('FederationBaseAuth',)


class _Rescoped(base.BaseAuth, metaclass=abc.ABCMeta):
    """A plugin that is always going to go through a rescope process.

    The original keystone plugins could simply pass a project or domain to
    along with the credentials and get a scoped token. For federation, K2K and
    newer mechanisms we always get an unscoped token first and then rescope.

    This is currently not public as it's generally an abstraction of a flow
    used by plugins within keystoneauth1.

    It also cannot go in base as it depends on token.Token for rescoping which
    would create a circular dependency.

    Because the unscoped token outlives any single scope, this class extends
    the base caching with a parallel set of methods -
    :py:meth:`get_unscoped_cache_id`, :py:meth:`get_unscoped_auth_state` and
    :py:meth:`set_unscoped_auth_state` - that identify and carry that token
    without reference to the scope. The scope-aware ``get_cache_id`` and
    ``get_auth_state`` inherited from the base continue to describe the
    scoped token.
    """

    rescoping_plugin = token.Token

    #: The unscoped token, kept so that a caller can take it out and put it
    #: back on a later run. Not populated until an unscoped token has been
    #: obtained or installed.
    _unscoped_auth_ref: access.AccessInfoV3 | None = None

    def get_unscoped_cache_id_elements(self) -> dict[str, str | None]:
        """Return what identifies this plugin's unscoped token.

        A plugin that can describe its unscoped token overrides this; one
        that leaves it raising cannot describe it and so must not be cached.

        The elements must not include the scope. The point of the unscoped
        token is that it can be rescoped to any target, so one stored copy
        serves every scope.
        """
        raise NotImplementedError()

    def get_unscoped_cache_id(self) -> str | None:
        """Fetch an identifier for the unscoped token this plugin obtains.

        Unlike :py:meth:`get_cache_id`, this deliberately does not vary with
        the scope, so a caller can store one unscoped token and rescope it to
        any project, domain or system.

        Note that this identifies the plugin's configuration, not whoever
        ends up authenticating with it. For an interactive flow the identity
        is chosen in the browser and is not knowable here, so a caller
        storing tokens for more than one account has to add something of its
        own to distinguish them.

        :returns: A unique string, or None if the unscoped token cannot be
                  identified and so must not be stored.
        """
        try:
            elements = self.get_unscoped_cache_id_elements()
        except NotImplementedError:
            return None

        hasher = hashlib.sha256()
        for key, value in sorted(elements.items()):
            if value is None:
                continue
            # Terminate both, so that the elements cannot be read out of the
            # hash in more than one way.
            hasher.update(key.encode('utf-8'))
            hasher.update(b'\x00')
            hasher.update(value.encode('utf-8'))
            hasher.update(b'\x00')

        # Base64-encode the digest, the same encoding get_cache_id uses.
        return base64.b64encode(hasher.digest()).decode('utf-8')

    def get_unscoped_auth_state(self) -> str | None:
        """Retrieve the unscoped token, for a caller that wants to store it.

        Obtaining an unscoped token can be expensive, and for an interactive
        flow it cannot be repeated without the user. A caller that hands the
        result back through :py:meth:`set_unscoped_auth_state` on a later run
        skips that step and pays only for the rescope.

        This does not fetch anything: it returns None until an unscoped token
        has been obtained.

        :returns: A string to store, or None if there is nothing to store.
        """
        if self._unscoped_auth_ref is None:
            return None

        return json.dumps(
            {
                'auth_token': self._unscoped_auth_ref.auth_token,
                'body': self._unscoped_auth_ref._data,
            }
        )

    def set_unscoped_auth_state(self, data: str | None) -> None:
        """Install a previously stored unscoped token.

        Takes what :py:meth:`get_unscoped_auth_state` returned. An expired
        token is accepted and simply discarded when it is next needed, so a
        caller does not have to check before installing one.

        :raises ValueError: The data is not something this method produced.
        """
        if not data:
            self._unscoped_auth_ref = None
            return

        parsed = json.loads(data)
        try:
            auth_ref = access.create(
                body=parsed['body'], auth_token=parsed['auth_token']
            )
        except (KeyError, TypeError):
            # KeyError for a dict missing our keys; TypeError when the JSON
            # decoded to something that is not a dict at all (a list, a
            # string, null), so the key lookup itself fails.
            raise ValueError('Not an unscoped auth state produced by this API')

        if not isinstance(auth_ref, access.AccessInfoV3):
            raise ValueError('Unscoped auth state is not an identity v3 token')

        self._unscoped_auth_ref = auth_ref

    def invalidate(self) -> bool:
        """Discard the current tokens, the unscoped one included.

        A session invalidates the plugin when a request comes back
        unauthorized. Keeping the unscoped token would mean rescoping from
        something the identity service has already rejected.
        """
        invalidated = super().invalidate()

        if self._unscoped_auth_ref is not None:
            self._unscoped_auth_ref = None
            invalidated = True

        return invalidated

    def get_auth_ref(self, session: ks_session.Session) -> access.AccessInfoV3:
        """Authenticate retrieve token information.

        This is a multi-step process where a client does federated authn
        receives an unscoped token.

        If an unscoped token is successfully received and scoping information
        is present then the token is rescoped to that target.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: a token data representation
        :rtype: :py:class:`keystoneauth1.access.AccessInfo`

        """
        auth_ref = self._unscoped_auth_ref
        reused = auth_ref is not None and not auth_ref.will_expire_soon(
            self.MIN_TOKEN_LIFE_SECONDS
        )

        if not reused:
            auth_ref = self._authenticate(session)

        # narrow type
        assert auth_ref is not None  # nosec B101

        try:
            return self._rescope(session, auth_ref)
        except exceptions.Unauthorized:
            if not reused:
                raise

            # An unscoped token installed from elsewhere can be refused for
            # reasons its expiry does not reveal, having been revoked being
            # the obvious one. Nothing recovers it, and the rescope request
            # carries the token in its body rather than a header, so the
            # session cannot retry this for us.
            LOG.debug(
                'The unscoped token was refused; authenticating again to '
                'replace it'
            )
            return self._rescope(session, self._authenticate(session))

    def _authenticate(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Fetch a new unscoped token and keep it."""
        auth_ref = self.get_unscoped_auth_ref(session)
        self._unscoped_auth_ref = auth_ref
        return auth_ref

    def _rescope(
        self, session: ks_session.Session, auth_ref: access.AccessInfoV3
    ) -> access.AccessInfoV3:
        """Rescope an unscoped token, if any scope was asked for."""
        # narrow type
        assert auth_ref.auth_token is not None  # nosec B101

        if not any(
            [
                self.trust_id,
                self.system_scope,
                self.domain_id,
                self.domain_name,
                self.project_id,
                self.project_name,
                self.project_domain_id,
                self.project_domain_name,
            ]
        ):
            return auth_ref

        token_plugin = self.rescoping_plugin(
            self.auth_url,
            token=auth_ref.auth_token,
            trust_id=self.trust_id,
            system_scope=self.system_scope,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
        )

        return token_plugin.get_auth_ref(session)

    @abc.abstractmethod
    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Fetch unscoped federated token."""


class FederationBaseAuth(_Rescoped):
    """Federation authentication plugin.

    :param auth_url: URL of the Identity Service
    :type auth_url: string
    :param identity_provider: name of the Identity Provider the client
                              will authenticate against. This parameter
                              will be used to build a dynamic URL used to
                              obtain unscoped OpenStack token.
    :type identity_provider: string
    :param protocol: name of the protocol the client will authenticate
                     against.
    :type protocol: string

    """

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
    ):
        super().__init__(
            auth_url=auth_url,
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
        self.identity_provider = identity_provider
        self.protocol = protocol

    def get_unscoped_cache_id_elements(self) -> dict[str, str | None]:
        """What identifies the unscoped token a federated plugin obtains.

        The identity service issues it for a given identity provider and
        protocol at a given endpoint, so those describe it. The scope is
        applied afterwards and is deliberately left out.
        """
        return {
            'auth_url': self.auth_url,
            'identity_provider': self.identity_provider,
            'protocol': self.protocol,
        }

    @property
    def federated_token_url(self) -> str:
        """Full URL where authorization data is sent."""
        host = self.auth_url.rstrip('/')
        if not host.endswith('v3'):
            host += '/v3'
        values = {
            'host': host,
            'identity_provider': self.identity_provider,
            'protocol': self.protocol,
        }
        url = (
            "%(host)s/OS-FEDERATION/identity_providers/"
            "%(identity_provider)s/protocols/%(protocol)s/auth"
        )
        url = url % values

        return url
