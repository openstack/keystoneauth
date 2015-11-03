======
Extras
======

The extensibility of keystoneauth plugins is purposefully designed to allow a
range of different authentication mechanisms that don't have to reside in the
upstream packages. There are however a number of plugins that upstream supports
that involve additional dependencies that the keystoneauth package cannot
depend upon directly.

To get around this we utilize setuptools `extras dependencies <https://pythonhosted.org/setuptools/setuptools.html#declaring-extras-optional-features-with-their-own-dependencies>`_ for additional
plugins. To use a plugin like the kerberos plugin that has additional
dependencies you must install the additional dependencies like::

    pip install keystoneauth1[kerberos]

By convention (not a requirement) extra plugins have a module located in the
keystoneauth1.extras module with the same name as the dependency. eg::

    $ from keystoneauth1.extras import kerberos

There is no keystoneauth specific check that the correct dependencies are
installed for accessing a module. You would expect to see standard python
ImportError when the required dependencies are not found.
