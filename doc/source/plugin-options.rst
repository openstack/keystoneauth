==============
Plugin Options
==============

Usage
-----

Using plugins via CLI
~~~~~~~~~~~~~~~~~~~~~

Plugins can be configured via CLI options, using argparse's ``ArgumentParser``.
This is commonly used to produce client tooling that communicates with
OpenStack APIs and therefore needs to allow authentication. For example,
``openstackclient`` allows configuration using CLI options.

When using auth plugins via CLI you can specify parameters via CLI options or
via environment configuration, with CLI options superseding environment
configuration. CLI options are specified with the pattern ``--os-`` and the
parameter name. For example, to use the password_ plugin via CLI options you
can specify:

.. code-block:: bash

    openstack --os-auth-type password \
              --os-auth-url http://keystone.example.com:5000/ \
              --os-username myuser \
              --os-password mypassword \
              --os-project-name myproject \
              --os-default-domain-name mydomain \
              operation

Environment variables are specified using the pattern ``OS_`` followed by the
uppercase parameter name replacing ``-`` with ``_``. Using the password_
example again:

.. code-block:: bash

    export OS_AUTH_TYPE=password
    export OS_AUTH_URL=http://keystone.example.com:5000/
    export OS_USERNAME=myuser
    export OS_PASSWORD=mypassword
    export OS_PROJECT_NAME=myproject
    export OS_DEFAULT_DOMAIN_NAME=mydomain


Using plugins via ``clouds.yaml``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Plugins can be configured via ``clouds.yaml`` files, which are supported by
``openstacksdk``. When using a ``clouds.yaml``, you specify the plugin name as
``auth_type`` within the cloud entry and then specify all plugin options within
the ``auth`` key of the cloud entry. For example, to use the password_ plugin
for a cloud entry ``mycloud`` in a ``clouds.yaml`` file you can specify:

.. code-block:: yaml

    clouds:
      mycloud:
        auth_type: password
        auth:
          auth_url: http://keystone.example.com:5000/
          username: myuser
          password: mypassword
          project_name: myproject
          default_domain_name: mydomain


Using plugins via config file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Plugins can be configured using INI-style configuration file, using
oslo.config. This is commonly used to allow OpenStack service to talk to each
other though it can be used for any service that wishes to authenticate against
Keystone and uses oslo.config. For example, this configuration style is used to
allow the Compute service (Nova) to talk to the Networking service (Neutron),
Block Storage service (Cinder), and others.

When using the plugins via config file you define the plugin name as
``auth_type``. The options of the plugin are then specified while replacing
``-`` with ``_`` to be valid in configuration.

For example to use the password_ plugin in a config file you would specify:

.. code-block:: ini

    [section]
    auth_type = password
    auth_url = http://keystone.example.com:5000/
    username = myuser
    password = mypassword
    project_name = myproject
    default_domain_name = mydomain


Using plugins via other mechanisms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Beyond the three configuration mechanisms described here, different services
may implement loaders in their own way and you should consult their relevant
documentation. However, the same auth options will always be available.


Built-in Plugins
----------------

This is a listing of all included plugins and the options that they accept.
Plugins are listed alphabetically and not in any order of priority.

.. list-auth-plugins::


Additional Plugins
------------------

keystoneauth is designed to be pluggable and Python packages exist that
provide additional plugins.
