=============================
Migrating from keystoneclient
=============================

When keystoneauth was extracted from keystoneclient the basic usage of the
session, adapter and auth plugins purposefully did not change. If you are using
them in a supported fashion from keystoneclient then the transition should be
fairly simple.

Authentication Plugins
======================

The authentication plugins themselves changed very little however there were
changes to the way plugins are loaded and some of the supporting classes.

Plugin Loading
--------------

In keystoneclient auth plugin loading is managed by the class itself. This
method proved useful in allowing the plugin to control the way it was loaded
however it linked the authentication logic with the config and CLI loading.

In keystoneauth this has been severed and the auth plugin is handle seperately
from the mechanism that loads it.

Authentication plugins still implement the base authentication class
:py:class:`~keystoneauth1.plugin.BaseAuthPlugin`. To make the plugins capable
of being loaded from CLI or CONF file you implement a
:py:class:`~keystoneauth1.loading.BaseLoader` object that is loaded when a user
does '--os-auth-type', handles the options that are presented, and then
constructs the authentication plugin for use by the application.

Largely the options that are returned will be the same as what was used in
keystoneclient however in keystoneclient the options used
:py:class:`oslo_config.cfg.Opt` objects. Due to trying to keep minimal
dependencies there is no direct dependency from keystoneauth on oslo.config and
instead options should be specified as :py:class:`~keystoneauth1.loading.Opt`
objects.

To ensure distinction between the plugins the setuptools entypoints that
plugins register at has been updated to reflect keystoneauth1 and should now
be: keystoneauth1.plugin

AccessInfo Objects
------------------

AccessInfo objects are a representation of the information stored within a
token. In keystoneclient these objects were dictionaries of the token data with
property accessors. In keystoneauth the dictionary interface has been removed
and just the property accessors are available.

The creation function has also changed. The
:py:meth:`keystoneclient.access.AccessInfo.factory` method has been removed
and replaced with the :py:func:`keystoneauth1.access.create`.
