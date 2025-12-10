======================
Authentication Plugins
======================

Introduction
============

Authentication plugins provide a generic means by which to extend the
authentication mechanisms known to OpenStack clients.

In the vast majority of cases the authentication plugins used will be those
written for use with the OpenStack Identity Service (Keystone), however this is
not the only possible case, and the mechanisms by which authentication plugins
are used and implemented should be generic enough to cover completely
customized authentication solutions.

The subset of authentication plugins intended for use with an OpenStack
Identity server (such as Keystone) are called Identity Plugins.


Available Plugins
=================

Keystoneauth ships with a number of plugins and particularly Identity
Plugins.

V2 Identity Plugins
-------------------

Standard V2 identity plugins are defined in the module:
:py:mod:`keystoneauth1.identity.v2`

They include:

- :py:class:`~keystoneauth1.identity.v2.Password`: Authenticate against
  a V2 identity service using a username and password.
- :py:class:`~keystoneauth1.identity.v2.Token`: Authenticate against a
  V2 identity service using an existing token.

V2 identity plugins must use an `auth_url` that points to the root of a V2
identity server URL, i.e.: ``http://hostname:5000/v2.0``.

V3 Identity Plugins
-------------------

Standard V3 identity plugins are defined in the module
:py:mod:`keystoneauth1.identity.v3`.

V3 Identity plugins are slightly different from their V2 counterparts as a V3
authentication request can contain multiple authentication methods.  To handle
this V3 defines a number of different
:py:class:`~keystoneauth1.identity.v3.AuthMethod` classes:

- :py:class:`~keystoneauth1.identity.v3.PasswordMethod`: Authenticate
  against a V3 identity service using a username and password.
- :py:class:`~keystoneauth1.identity.v3.TokenMethod`: Authenticate against
  a V3 identity service using an existing token.
- :py:class:`~keystoneauth1.identity.v3.ReceiptMethod`: Authenticate against
  a V3 identity service using an existing auth-receipt. This method has to be
  used in conjunction with at least one other method.
- :py:class:`~keystoneauth1.identity.v3.TOTPMethod`: Authenticate against
  a V3 identity service using Time-Based One-Time Password (TOTP).
- :py:class:`~keystoneauth1.identity.v3.TokenlessAuth`: Authenticate against
  a V3 identity service using tokenless authentication.
- :py:class:`~keystoneauth1.identity.v3.ApplicationCredentialMethod`:
  Authenticate against a V3 identity service using an application credential.
- :py:class:`~keystoneauth1.extras.kerberos.KerberosMethod`: Authenticate
  against a V3 identity service using Kerberos.
- :py:class:`~keystoneauth1.identity.v3.OAuth2ClientCredentialMethod`:
  Authenticate against a V3 identity service using an OAuth2.0 client
  credential.
- :py:class:`~keystoneauth1.identity.v3.OAuth2mTlsClientCredential`:
  Authenticate against a V3 identity service using an OAuth2.0 Mutual-TLS
  client credentials.

The :py:class:`~keystoneauth1.identity.v3.AuthMethod` objects are then
passed to the :py:class:`~keystoneauth1.identity.v3.Auth` plugin::

    >>> from keystoneauth1 import session
    >>> from keystoneauth1.identity import v3
    >>> password = v3.PasswordMethod(username='user',
    ...                              password='password',
    ...                              user_domain_name='default')
    >>> auth = v3.Auth(auth_url='http://my.keystone.com:5000/v3',
    ...                auth_methods=[password],
    ...                project_id='projectid')
    >>> sess = session.Session(auth=auth)

You can even add additional methods to an existing auth instance after it
has been created::

    >>> totp = v3.TOTPMethod(username='user',
    ...                      passcode='123456',
    ...                      user_domain_name='default')
    >>> auth.add_method(totp)

Or use the :py:class:`~keystoneauth1.identity.v3.MultiFactor` helper
plugin to do it all simply in one go, an example of whichs exists in the
section below.

For the common cases where you will only want to use one
:py:class:`~keystoneauth1.identity.v3.AuthMethod` there are also helper
authentication plugins for the various
:py:class:`~keystoneauth1.identity.v3.AuthMethod` which can be used more
like the V2 plugins:

- :py:class:`~keystoneauth1.identity.v3.Password`: Authenticate using
  only a :py:class:`~keystoneauth1.identity.v3.PasswordMethod`.
- :py:class:`~keystoneauth1.identity.v3.Token`: Authenticate using only a
  :py:class:`~keystoneauth1.identity.v3.TokenMethod`.
- :py:class:`~keystoneauth1.identity.v3.TOTP`: Authenticate using
  only a :py:class:`~keystoneauth1.identity.v3.TOTPMethod`.
- :py:class:`~keystoneauth1.extras.kerberos.Kerberos`: Authenticate using
  only a :py:class:`~keystoneauth1.extras.kerberos.KerberosMethod`.

::

    >>> auth = v3.Password(auth_url='http://my.keystone.com:5000/v3',
    ...                    username='username',
    ...                    password='password',
    ...                    project_id='projectid',
    ...                    user_domain_name='default')
    >>> sess = session.Session(auth=auth)

This will have exactly the same effect as using the single
:py:class:`~keystoneauth1.identity.v3.PasswordMethod` above.

V3 identity plugins must use an `auth_url` that points to the root of a V3
identity server URL, i.e.: ``http://hostname:5000/v3``.

Multi-Factor with V3 Identity Plugins
-------------------------------------

The basic example of multi-factor authentication is when you supply all the
needed auth methods up front.

This can be done by building an Auth class with method instances:

.. code-block:: python

    from keystoneauth1 import session
    from keystoneauth1.identity import v3

    auth = v3.Auth(
        auth_url='http://my.keystone.com:5000/v3',
        auth_methods=[
            v3.PasswordMethod(
                username='user',
                password='password',
                user_domain_id="default",
            ),
            v3.TOTPMethod(
                username='user',
                passcode='123456',
                user_domain_id="default",
            )
        ],
        project_id='projectid',
    )
    sess = session.Session(auth=auth)

Or by letting the helper plugin do it for you:

.. code-block:: python

    from keystoneauth1 import session
    from keystoneauth1.identity import v3

    auth = v3.MultiFactor(
        auth_url='http://my.keystone.com:5000/v3',
        auth_methods=['v3password', 'v3totp'],
        username='user',
        password='password',
        passcode='123456',
        user_domain_id="default",
        project_id='projectid',
    )
    sess = session.Session(auth=auth)

**Note:** The :py:class:`~keystoneauth1.identity.v3.MultiFactor` helper
does not support auth receipts as an option in auth_methods, but one can
be added with `auth.add_method`.

When you supply just one method when multiple are needed, a
:py:class:`~keystoneauth1.exceptions.auth.MissingAuthMethods` error will
be raised. This can be caught, and you can infer based on the error what
the missing methods were, and from it extract the receipt to continue
authentication:

.. code-block:: python

    auth = v3.Password(auth_url='http://my.keystone.com:5000/v3',
                       username='username',
                       password='password',
                       project_id='projectid',
                       user_domain_id='default')
    sess = session.Session(auth=auth)
    try:
       sess.get_token()
    except exceptions.MissingAuthMethods as e:
        receipt = e.receipt
        methods = e.methods
        required_methods = e.required_auth_methods

Once you know what auth methods are needed to continue, you can extend
the existing auth plugin with additional methods:

.. code-block:: python

    auth.add_method(
        v3.TOTPMethod(
            username='user',
            passcode='123456',
            user_domain_id='default',
        )
    )
    sess.get_token()

Or if you do not have the existing auth method, but have the receipt
you can continue as well:

.. code-block:: python

    auth = v3.TOTP(
        auth_url='http://my.keystone.com:5000/v3',
        username='user',
        passcode='123456',
        user_domain_id='default',
        project_id='projectid',
    )
    auth.add_method(v3.ReceiptMethod(receipt=receipt))
    sess = session.Session(auth=auth)
    sess.get_token()

Standalone Plugins
------------------

Services can be deployed in a standalone environment where there is no integration
with an identity service. The following plugins are provided to support standalone
services:

- :py:class:`~keystoneauth1.http_basic.HTTPBasicAuth`: HTTP Basic authentication
- :py:class:`~keystoneauth1.noauth.NoAuth`: No authentication

Standalone plugins must be given an `endpoint` that points to the URL of the one
service being used, since there is no service catalog to look up endpoints::

    from keystoneauth1 import session
    from keystoneauth1 import noauth
    auth = noauth.NoAuth(endpoint='http://hostname:6385/')
    sess = session.Session(auth=auth)

:py:class:`~keystoneauth1.http_basic.HTTPBasicAuth` also requres a `username` and
`password`::

    from keystoneauth1 import session
    from keystoneauth1 import http_basic
    auth = http_basic.HTTPBasicAuth(endpoint='http://hostname:6385/',
                                    username='myUser',
                                    password='myPassword')
    sess = session.Session(auth=auth)

Federation
==========

The following V3 plugins are provided to support federation:

- :py:class:`~keystoneauth1.extras.kerberos.MappedKerberos`: Federated (mapped)
  Kerberos.
- :py:class:`~keystoneauth1.extras._saml2.v3.Password`: SAML2 password
  authentication.
- :py:class:`~keystoneauth1.identity.v3:OpenIDConnectAccessToken`: Plugin to
  reuse an existing OpenID Connect access token.
- :py:class:`~keystoneauth1.identity.v3:OpenIDConnectAuthorizationCode`: OpenID
  Connect Authorization Code grant type.
- :py:class:`~keystoneauth1.identity.v3:OpenIDConnectClientCredentials`: OpenID
  Connect Client Credentials grant type.
- :py:class:`~keystoneauth1.identity.v3:OpenIDConnectPassword`: OpenID Connect
  Resource Owner Password Credentials grant type.
- :py:class:`~keystoneauth1.identity.v3.Keystone2Keystone`: Keystone to
  Keystone Federation.

The Keystone2Keystone plugin is special as it takes a Password auth for one
keystone instance acting as an Identity Provider as input in order to create a
session on the keystone acting as a Service Provider, for example:

.. code-block:: python

    from keystoneauth1 import session
    from keystoneauth1.identity import v3
    from keystoneauth1.identity.v3 import k2k

    pwauth = v3.Password(auth_url='http://my.keystone.com:5000/v3',
                         username='username',
                         password='password',
                         project_id='projectid',
                         user_domain_name='Default')
    k2kauth = k2k.Keystone2Keystone(pwauth, 'mysp',
                                    project_id='federated_projectid')
    k2ksession = session.Session(auth=k2kauth)


The `OpenIDConnectPassword` plugin also supports OTP. This option is required
in cases when the Identity Provider requires more than a password to
authenticate the user. As the OTP usually is a short-lived code that
continually changes, then, when this option is active, the user will be
requested to input the OTP code when executing the authentication process.

To enable this option, the user will need to export the environment variable
"OS_IDP_OTP_KEY" with the OTP key used by the Identity Provider's
authentication API.

E.g.: If the Identity Provider's authentication API requires some JSON like:

.. code-block:: json

    {
        "username": "user1",
        "password": "passwd",
        "totp": "763907"
    }

Then, you will use the "totp" value in your "OS_IDP_OTP_KEY", something like
"export OS_IDP_OTP_KEY=totp".

After the configuration of the "OS_IDP_OTP_KEY" environment variable,
every time that you will log in through the python openstack-client, a prompt
will be displayed requesting to you to input your OTP code.

Version Independent Identity Plugins
------------------------------------

Standard version independent identity plugins are defined in the module
:py:mod:`keystoneauth1.identity.generic`.

For the cases of plugins that exist under both the identity V2 and V3 APIs
there is an abstraction to allow the plugin to determine which of the V2 and V3
APIs are supported by the server and use the most appropriate API.

These plugins are:

- :py:class:`~keystoneauth1.identity.generic.Password`: Authenticate
  using a user/password against either v2 or v3 API.
- :py:class:`~keystoneauth1.identity.generic.Token`: Authenticate using
  an existing token against either v2 or v3 API.

These plugins work by first querying the identity server to determine available
versions and so the `auth_url` used with the plugins should point to the base
URL of the identity server to use. If the `auth_url` points to either a V2 or
V3 endpoint it will restrict the plugin to only working with that version of
the API.

Simple Plugins
--------------

In addition to the Identity plugins a simple plugin that will always use the
same provided token and endpoint is available. This is useful for situations
where you have a token and want to bypass authentication to obtain a new token
for subsequent requests. Testing, proxies, and service-to-service
authentication on behalf of a user are good examples use cases for this
authentication plugin.

It can be found at :py:class:`keystoneauth1.token_endpoint.Token`.

For example::

    >>> from keystoneauth1 import token_endpoint
    >>> from keystoneauth1 import session
    >>> a = token_endpoint.Token('http://my.keystone.com:5000/v3',
    ...                          token=token)
    >>> s = session.Session(auth=a)


V3 OAuth 1.0a Plugins
---------------------

There also exists a plugin for OAuth 1.0a authentication. We provide a helper
authentication plugin at:
:py:class:`~keystoneauth1.extras.oauth1.V3OAuth1`.
The plugin requires the OAuth consumer's key and secret, as well as the OAuth
access token's key and secret. For example::

    >>> from keystoneauth1.extras import oauth1
    >>> from keystoneauth1 import session
    >>> a = oauth1.V3OAuth1('http://my.keystone.com:5000/v3',
    ...                     consumer_key=consumer_id,
    ...                     consumer_secret=consumer_secret,
    ...                     access_key=access_token_key,
    ...                     access_secret=access_token_secret)
    >>> s = session.Session(auth=a)


Application Credentials
=======================

There is a specific authentication method for interacting with Identity servers
that support application credential authentication. Since application
credentials are associated to a user on a specific project, some parameters are
not required as they would be with traditional password authentication. The
following method can be used to authenticate for a token using an application
credential:

- :py:class:`~keystoneauth1.identity.v3.ApplicationCredential`:

The following example shows the method usage with a session::

    >>> from keystoneauth1 import session
    >>> from keystone.identity import v3
    >>> auth = v3.ApplicationCredential(
            application_credential_secret='application_credential_secret',
            application_credential_id='c2872b920853478292623be94b657090'
        )
    >>> sess = session.Session(auth=auth)


OAuth2.0 Client Credentials
===========================

.. warning::

   The access token must be only added for the requests using HTTPS according
   to `RFC6749`_.

There is a specific authentication method for interacting with Identity
servers that support OAuth2.0 Client Credential Grant. The notable difference
from the other authentication method is that, after passing the
authentication, the ``session`` will add "Authorization" header with an
OAuth2.0 access token to sent subsequent requests. The following method can be
used to authenticate for a token using OAuth2.0 client credentials:

.. _RFC6749: https://datatracker.ietf.org/doc/html/rfc6749

- :py:class:`~keystoneauth1.identity.v3.OAuth2ClientCredential`:

The following example shows the method usage with a session::

    >>> from keystoneauth1 import session
    >>> from keystone.identity import v3
    >>> auth = v3.OAuth2ClientCredential(
            oauth2_endpoint='https://keystone.host/identity/v3/OS-OAUTH2/token'
            oauth2_client_id='f96a2fec117141a6b5fbaa0485632244',
            oauth2_client_secret='client_credential_secret'
        )
    >>> sess = session.Session(auth=auth)


OAuth2.0 Mutual-TLS Client Credentials
======================================

.. warning::

   The access token must be only added for the requests using mutual TLS
   according to `RFC8705`_.

There is a specific authentication method for interacting with Identity
servers that support OAuth 2.0 Mutual-TLS Client Authentication. The notable
difference from the other authentication method is that, after passing the
authentication, the ``session`` will add "Authorization" header with an
OAuth2.0 Certificate-Bound Access Tokens to sent subsequent requests. The
following method can be used to authenticate for a token using OAuth2.0
Mutual-TLS client credentials:

.. _RFC8705: https://datatracker.ietf.org/doc/html/rfc8705

- :py:class:`~keystoneauth1.identity.v3.OAuth2mTlsClientCredential`:

The following example shows the method usage with a session::

    >>> from keystoneauth1 import session
    >>> from keystone.identity import v3
    >>> auth = v3.OAuth2mTlsClientCredential(
            auth_url='http://keystone.host:5000/v3'
            oauth2_endpoint='https://keystone.host/identity/v3/OS-OAUTH2/token'
            oauth2_client_id='f96a2fec117141a6b5fbaa0485632244'
        )
    >>> sess = session.Session(auth=auth)


Tokenless Auth
==============

A plugin for tokenless authentication also exists. It provides a means to
authorize client operations within the Identity server by using an X.509
TLS client certificate without having to issue a token. We provide a
tokenless authentication plugin at:

- :class:`~keystoneauth1.identity.v3.TokenlessAuth`

It is mostly used by service clients for token validation and here is
an example of how this plugin would be used in practice::

    >>> from keystoneauth1 import session
    >>> from keystoneauth1.identity import v3
    >>> auth = v3.TokenlessAuth(auth_url='https://keystone:5000/v3',
    ...                         domain_name='my_service_domain')
    >>> sess = session.Session(
    ...                 auth=auth,
    ...                 cert=('/opt/service_client.crt',
    ...                       '/opt/service_client.key'),
    ...                 verify='/opt/ca.crt')


Loading Plugins by Name
=======================

In auth_token middleware and for some service to service communication it is
possible to specify a plugin to load via name. The authentication options that
are available are then specific to the plugin that you specified. Currently the
authentication plugins that are available in `keystoneauth` are:

- http_basic: :py:class:`keystoneauth1.http_basic.HTTPBasicAuth`
- none: :py:class:`keystoneauth1.noauth.NoAuth`
- password: :py:class:`keystoneauth1.identity.generic.Password`
- token: :py:class:`keystoneauth1.identity.generic.Token`
- v2password: :py:class:`keystoneauth1.identity.v2.Password`
- v2token: :py:class:`keystoneauth1.identity.v2.Token`
- v3applicationcredential: :py:class:`keystoneauth1.identity.v3.ApplicationCredential`
- v3password: :py:class:`keystoneauth1.identity.v3.Password`
- v3token: :py:class:`keystoneauth1.identity.v3.Token`
- v3fedkerb: :py:class:`keystoneauth1.extras.kerberos.MappedKerberos`
- v3kerberos: :py:class:`keystoneauth1.extras.kerberos.Kerberos`
- v3oauth1: :py:class:`keystoneauth1.extras.oauth1.v3.OAuth1`
- v3oidcaccesstoken: :py:class:`keystoneauth1.identity.v3:OpenIDConnectAccessToken`
- v3oidcauthcode: :py:class:`keystoneauth1.identity.v3:OpenIDConnectAuthorizationCode`
- v3oidcdeviceauthz: :py:class:`keystoneauth1.loading._plugins.identity.v3:OpenIDConnectDeviceAuthorization`
- v3oidcclientcredentials: :py:class:`keystoneauth1.identity.v3:OpenIDConnectClientCredentials`
- v3oidcpassword: :py:class:`keystoneauth1.identity.v3:OpenIDConnectPassword`
- v3samlpassword: :py:class:`keystoneauth1.extras._saml2.v3.Password`
- v3tokenlessauth: :py:class:`keystoneauth1.identity.v3.TokenlessAuth`
- v3totp: :py:class:`keystoneauth1.identity.v3.TOTP`
- v3oauth2clientcredential: :py:class:`keystoneauth1.identity.v3.OAuth2ClientCredential`
- v3oauth2mtlsclientcredential: :py:class:`keystoneauth1.identity.v3.OAuth2mTlsClientCredential`


Creating Authentication Plugins
===============================

Creating an Identity Plugin
---------------------------

If you have implemented a new authentication mechanism into the Identity
service then you will be able to reuse a lot of the infrastructure available
for the existing Identity mechanisms. As the V2 identity API has been removed,
it is expected that new plugins are for the V3 API.

To implement a new V3 plugin that can be combined with others you should
implement the base :py:class:`keystoneauth1.identity.v3.AuthMethod` class
and implement the
:py:meth:`~keystoneauth1.identity.v3.AuthMethod.get_auth_data` function.
If your Plugin cannot be used in conjunction with existing
:py:class:`keystoneauth1.identity.v3.AuthMethod` then you should just
override :py:class:`keystoneauth1.identity.v3.Auth` directly.

The new :py:class:`~keystoneauth1.identity.v3.AuthMethod` should take all
the required parameters via
:py:meth:`~keystoneauth1.identity.v3.AuthMethod.__init__` and return from
:py:meth:`~keystoneauth1.identity.v3.AuthMethod.get_auth_data` a tuple
with the unique identifier of this plugin (e.g. *password*) and a dictionary
containing the payload of values to send to the authentication server. The
session, calling auth object and request headers are also passed to this
function so that the plugin may use or manipulate them.

You should also provide a class that inherits from
:py:class:`keystoneauth1.identity.v3.Auth` with an instance of your new
:py:class:`~keystoneauth1.identity.v3.AuthMethod` as the `auth_methods`
parameter to :py:class:`keystoneauth1.identity.v3.Auth`.

By convention (and like above) these are named `PluginType` and
`PluginTypeMethod` (for example
:py:class:`~keystoneauth1.identity.v3.Password` and
:py:class:`~keystoneauth1.identity.v3.PasswordMethod`).


Creating a Custom Plugin
------------------------

To implement an entirely new plugin you should implement the base class
:py:class:`keystoneauth1.plugin.BaseAuthPlugin` and provide the
:py:meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_endpoint`,
:py:meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_token` and
:py:meth:`~keystoneauth1.plugin.BaseAuthPlugin.invalidate` methods.

:py:meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_token` is called to retrieve
the string token from a plugin. It is intended that a plugin will cache a
received token and so if the token is still valid then it should be re-used
rather than fetching a new one. A session object is provided with which the
plugin can contact it's server. (Note: use `authenticated=False` when making
those requests or it will end up being called recursively). The return value
should be the token as a string.

:py:meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_endpoint` is called to
determine a base URL for a particular service's requests. The keyword arguments
provided to the function are those that are given by the `endpoint_filter`
variable in :py:meth:`keystoneauth1.session.Session.request`. A session object
is also provided so that the plugin may contact an external source to determine
the endpoint.  Again this will be generally be called once per request and so
it is up to the plugin to cache these responses if appropriate. The return
value should be the base URL to communicate with.

:py:meth:`~keystoneauth1.plugin.BaseAuthPlugin.invalidate` should also be
implemented to clear the current user credentials so that on the next
:py:meth:`~keystoneauth1.plugin.BaseAuthPlugin.get_token` call a new token can
be retrieved.

The most simple example of a plugin is the
:py:class:`keystoneauth1.token_endpoint.Token` plugin.
