==============
Service Tokens
==============

Introduction
============

OpenStack services regularly communicate with each other on behalf of an end
user. For example, the Compute service (Nova) calls the Block Storage service
(Cinder) to attach a volume and the Networking service (Neutron) to configure
ports. These operations can take significant time to complete, and a user's
authentication token (``X-Auth-Token``) has a limited lifespan (typically one
hour). In complex, multi-step operations (such as live migration, volume
backups, or cluster provisioning), the initial user token may expire while
subsequent API calls between services are still taking place. Without a
mechanism to refresh or validate the user's ongoing request, those downstream
calls fail with an HTTP 401 (Unauthorized) error.

To solve this problem, OpenStack supports **service tokens**. A service token
is a secondary authentication token issued to a designated service user account
(such as ``nova`` or ``cinder``) and transmitted in the ``X-Service-Token``
HTTP header alongside the user's ``X-Auth-Token`` header.

How Service Tokens Work
=======================

When downstream services (such as Cinder, Glance, or Neutron) receive an
incoming request, their `keystonemiddleware`_ authentication filter inspects
both headers:

* **User Token (``X-Auth-Token``)**: Identifies the end user and project on
  whose behalf the action is taken.

* **Service Token (``X-Service-Token``)**: Identifies the trusted OpenStack
  service making the request.

If the receiving service has service token validation enabled, the middleware
verifies that the service token is valid and possesses a recognized service role
(such as ``service``). Once verified:

* The request is permitted to proceed even if the end user's token has expired,
  provided the overall operation was initiated when the user token was valid.

* The target service can distinguish between requests originating directly from
  an end user and those made by an authorized internal OpenStack service.

For more details on configuring service users in the Identity service, refer to
the `Keystone documentation on managing service users`__.

.. _keystonemiddleware: https://docs.openstack.org/keystonemiddleware/latest/
.. __: https://docs.openstack.org/keystone/latest/admin/manage-services.html

ServiceTokenAuthWrapper
=======================

In `keystoneauth1`, support for service tokens is implemented via the
:class:`~keystoneauth1.service_token.ServiceTokenAuthWrapper` class. This is a
composite plugin that wraps two separate authentication plugins:

* ``user_auth``: An instance of :class:`~keystoneauth1.plugin.BaseAuthPlugin`
  representing the primary user context. This plugin provides the
  ``X-Auth-Token`` header and is responsible for all endpoint discovery,
  version negotiation, and identity queries.

* ``service_auth``: An instance of :class:`~keystoneauth1.plugin.BaseAuthPlugin`
  representing the service account. This plugin provides the credentials
  needed to fetch a service token for the ``X-Service-Token`` header.

Delegation Behavior
-------------------

The wrapper delegates almost all plugin operations to ``user_auth``:

* **Headers**: Calls :meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_headers`
  on ``user_auth`` and attaches ``X-Service-Token`` using the token retrieved
  from ``service_auth.get_token(session)``.

* **Endpoint Discovery & Catalog**: Methods like
  :meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_endpoint`,
  :meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_endpoint_data`, and
  :meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_api_major_version` are
  delegated exclusively to ``user_auth``. This ensures service catalog
  resolution and version negotiation always reflect the user's project scope
  and permissions.

* **Identity Attributes**: Methods such as
  :meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_user_id` and
  :meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_project_id` delegate to
  ``user_auth``.

* **Connection Parameters**: Merges parameters from both plugins via
  :meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_connection_params`, giving
  priority to ``user_auth`` in case of conflict.

Programmatic Usage
==================

Forwarding an Incoming User Token
---------------------------------

The most common use case in OpenStack services is receiving an existing user
token from an incoming HTTP request (via request context) and forwarding it to
another service alongside the calling service's own credentials:

.. code-block:: python

    from keystoneauth1 import identity
    from keystoneauth1 import service_token
    from keystoneauth1 import session

    # 1. Primary user authentication using an existing token
    user_auth = identity.v3.Token(
        auth_url='https://identity.example.com/identity/v3',
        token='user-token-received-from-request',
    )

    # 2. Service authentication using the calling service's credentials
    service_auth = identity.v3.Password(
        auth_url='https://identity.example.com/identity/v3',
        username='nova',
        password='service-password',
        user_domain_name='Default',
        project_name='service',
        project_domain_name='Default',
    )

    # 3. Combine both plugins into the wrapper
    auth = service_token.ServiceTokenAuthWrapper(
        user_auth=user_auth,
        service_auth=service_auth,
    )

    # 4. Create an authenticated Session
    sess = session.Session(auth=auth)

Every HTTP request sent through ``sess`` will contain both ``X-Auth-Token`` and
``X-Service-Token`` headers.

Using with an Adapter
---------------------

In OpenStack client libraries and services, HTTP communication is typically
performed using :class:`~keystoneauth1.adapter.Adapter`. Because
:class:`~keystoneauth1.service_token.ServiceTokenAuthWrapper` delegates endpoint
and version discovery to ``user_auth``, it works seamlessly with adapters:

.. code-block:: python

    from keystoneauth1 import adapter

    # Create an adapter for the target service (e.g. Cinder / Block Storage)
    cinder_client = adapter.Adapter(
        session=sess,
        service_type='block-storage',
        interface='public',
    )

    # The adapter automatically discovers the endpoint from the user's catalog
    # and transmits both X-Auth-Token and X-Service-Token headers
    resp = cinder_client.get('/types')

Combining Fixed Credentials
---------------------------

You can also wrap two credential-based plugins (such as two
:class:`~keystoneauth1.identity.v3.Password` instances) for scripts, testing,
or tooling that acts as both a specific end user and a service:

.. code-block:: python

    user_auth = identity.v3.Password(
        auth_url='https://identity.example.com/identity/v3',
        username='jdoe',
        password='user-password',
        user_domain_name='Default',
        project_name='demo',
        project_domain_name='Default',
    )

    service_auth = identity.v3.Password(
        auth_url='https://identity.example.com/identity/v3',
        username='nova',
        password='service-password',
        user_domain_name='Default',
        project_name='service',
        project_domain_name='Default',
    )

    auth = service_token.ServiceTokenAuthWrapper(
        user_auth=user_auth,
        service_auth=service_auth,
    )
    sess = session.Session(auth=auth)

Usage with oslo.config
======================

In OpenStack services, client sessions and authentication options are loaded
dynamically using `oslo.config`_ via :mod:`keystoneauth1.loading`.

Configuration File
------------------

Services typically configure service user credentials in a dedicated
configuration section (conventionally named ``[service_user]``):

.. code-block:: ini

    [service_user]
    auth_type = password
    auth_url = https://identity.example.com/identity/v3
    project_domain_name = Default
    project_name = service
    user_domain_name = Default
    username = nova
    password = secret-nova-password

Loading and Wrapping
--------------------

In service code, the ``service_auth`` plugin is loaded from configuration, while
``user_auth`` is obtained from the incoming request context (which provides an
auth plugin populated with the incoming user token):

.. code-block:: python

    from keystoneauth1 import adapter
    from keystoneauth1 import loading as ks_loading
    from keystoneauth1 import service_token
    from oslo_config import cfg

    CONF = cfg.CONF

    # Register standard session and auth options for the service user group
    ks_loading.register_session_conf_options(CONF, 'service_user')
    ks_loading.register_auth_conf_options(CONF, 'service_user')

    # Load service user credentials from config
    service_auth = ks_loading.load_auth_from_conf_options(CONF, 'service_user')

    # Obtain user auth from the request context (e.g. in Nova or Cinder)
    user_auth = context.get_auth_plugin()

    # Wrap the user auth and service auth
    auth = service_token.ServiceTokenAuthWrapper(
        user_auth=user_auth,
        service_auth=service_auth,
    )

    # Load a session and create an adapter for the target service
    sess = ks_loading.load_session_from_conf_options(
        CONF, 'cinder', auth=auth
    )
    cinder = adapter.Adapter(session=sess, service_type='block-storage')

Sending services usually guard the wrapping logic behind an operator
configuration option (such as ``[service_user] send_service_user_token = true``)
so that service token transmission can be toggled by operators.

.. _oslo.config: https://docs.openstack.org/oslo.config/latest/

Token Invalidation
==================

Calling :meth:`~keystoneauth1.service_token.ServiceTokenAuthWrapper.invalidate`
invalidates both the ``user_auth`` and ``service_auth`` token caches:

.. code-block:: python

    auth.invalidate()

If an HTTP request fails with an HTTP 401 Unauthorized status,
:class:`~keystoneauth1.session.Session` invokes this method automatically to
ensure that expired tokens on either side are refreshed on the subsequent retry.
