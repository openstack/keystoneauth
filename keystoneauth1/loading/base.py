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

import six
import stevedore

from keystoneauth1 import exceptions

PLUGIN_NAMESPACE = 'keystoneauth1.plugin'


def get_available_plugin_names():
    """Get the names of all the plugins that are available on the system.

    This is particularly useful for help and error text to prompt a user for
    example what plugins they may specify.

    :returns: A list of names.
    :rtype: frozenset
    """
    mgr = stevedore.ExtensionManager(namespace=PLUGIN_NAMESPACE)
    return frozenset(mgr.names())


def get_available_plugin_loaders():
    """Retrieve all the plugin classes available on the system.

    :returns: A dict with plugin entrypoint name as the key and the plugin
              class as the value.
    :rtype: dict
    """
    mgr = stevedore.ExtensionManager(namespace=PLUGIN_NAMESPACE,
                                     propagate_map_exceptions=True)

    return dict(mgr.map(lambda ext: (ext.entry_point.name, ext.plugin)))


def get_plugin_loader(name):
    """Retrieve a plugin class by its entrypoint name.

    :param str name: The name of the object to get.

    :returns: An auth plugin class.
    :rtype: :py:class:`keystoneauth1.loading.BaseLoader`

    :raises keystonauth.exceptions.NoMatchingPlugin: if a plugin cannot be
                                                        created.
    """
    try:
        mgr = stevedore.DriverManager(namespace=PLUGIN_NAMESPACE,
                                      name=name)
    except RuntimeError:
        raise exceptions.NoMatchingPlugin(name)

    return mgr.driver


@six.add_metaclass(abc.ABCMeta)
class BaseLoader(object):

    @abc.abstractproperty
    def plugin_class(self):
        raise NotImplemented()

    @abc.abstractmethod
    def get_options(self):
        """Return the list of parameters associated with the auth plugin.

        This list may be used to generate CLI or config arguments.

        :returns: A list of Param objects describing available plugin
                  parameters.
        :rtype: list
        """
        return []

    def load_from_options(self, **kwargs):
        """Create a plugin from the arguments retrieved from get_options.

        A client can override this function to do argument validation or to
        handle differences between the registered options and what is required
        to create the plugin.
        """
        return self.plugin_class(**kwargs)

    def register_argparse_arguments(self, parser):
        """Register the CLI options provided by a specific plugin.

        Given a plugin class convert it's options into argparse arguments and
        add them to a parser.

        :param parser: the parser to attach argparse options.
        :type parser: argparse.ArgumentParser
        """
        for opt in self.get_options():
            parser.add_argument(*opt.argparse_args,
                                default=opt.argparse_default,
                                metavar=opt.metavar,
                                help=opt.help,
                                dest='os_%s' % opt.dest)

    def load_from_argparse_arguments(self, namespace, **kwargs):
        """Load a specific plugin object from an argparse result.

        Convert the results of a parse into the specified plugin.

        :param namespace: The result from CLI parsing.
        :type namespace: argparse.Namespace

        :returns: An auth plugin, or None if a name is not provided.
        :rtype: :py:class:`keystonauth.auth.BaseAuthPlugin`
        """

        def _getter(opt):
            return getattr(namespace, 'os_%s' % opt.dest)

        return self.load_from_options_getter(_getter, **kwargs)

    def register_conf_options(self, conf, group):
        """Register the oslo_config options that are needed for a plugin.

        :param conf: A config object.
        :type conf: oslo_config.cfg.ConfigOpts
        :param string group: The group name that options should be read from.
        """
        plugin_opts = [o._to_oslo_opt() for o in self.get_options()]
        conf.register_opts(plugin_opts, group=group)

    def load_from_conf_options(self, conf, group, **kwargs):
        """Load the plugin from a CONF object.

        Convert the options already registered into a real plugin.

        :param conf: A config object.
        :type conf: oslo_config.cfg.ConfigOpts
        :param string group: The group name that options should be read from.

        :returns: An authentication Plugin.
        :rtype: :py:class:`keystonauth.auth.BaseAuthPlugin`
        """

        def _getter(opt):
            return conf[group][opt.dest]

        return self.load_from_options_getter(_getter, **kwargs)

    def load_from_options_getter(self, getter, **kwargs):
        """Load a plugin from a getter function that returns appropriate values

        To handle cases other than the provided CONF and CLI loading you can
        specify a custom loader function that will be queried for the option
        value.

        The getter is a function that takes one value, a
        :py:class:`keystoneauth1.loading.Opt` and returns a value to load with.

        :param getter: A function that returns a value for the given opt.
        :type getter: callable

        :returns: An authentication Plugin.
        :rtype: :py:class:`keystonauth.auth.BaseAuthPlugin`
        """

        plugin_opts = self.get_options()

        for opt in plugin_opts:
            val = getter(opt)
            if val is not None:
                val = opt.type(val)
            kwargs.setdefault(opt.dest, val)

        return self.load_from_options(**kwargs)
