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
                                      invoke_on_load=True,
                                      name=name)
    except RuntimeError:
        raise exceptions.NoMatchingPlugin(name)

    return mgr.driver


def _find_winning_auth_value(opt, config):
    opt_name = opt.name.replace('-', '_')
    if opt_name in config:
        return config[opt_name]
    else:
        for d_opt in opt.deprecated_opts:
            d_opt_name = d_opt.name.replace('-', '_')
            if d_opt_name in config:
                return config[d_opt_name]


def _dashes_to_underscores(in_dict):
    out_dict = {}
    for key, value in in_dict.items():
        out_dict[key.replace('-', '_')] = value
    return out_dict


def validate_auth(config):
    """Validate and extract the auth parameters from the given dict.

    Given a dictionary of parameters, extract a normalized dictionary
    of parameters suitable for passing to an auth plugin constructor.

    Because it's working with input and output dictionaries, and because the
    targets are input parameters to constructors, normalize to underscores.

    :param dict config: The config dictionary containing the values to process

    :returns: An tuple with two dicts. The first dict is a copy of the input
        dict, scrubbed of auth parameters. The second dict are the auth
        parameters. Both will have all keys normalized to underscores.

    :raises keystoneauth1.exceptions.MissingRequiredParameters:
        if a required parameter is not provided.
    """
    config = _dashes_to_underscores(config)
    auth_params = _dashes_to_underscores(config.pop('auth', {}))

    auth_plugin = get_plugin_loader(config['auth_type'])

    plugin_options = auth_plugin.get_options()
    missing_required = []

    for p_opt in plugin_options:
        # if it's in auth_params, win, kill it from config dict
        # if it's in config and not in auth_params, move it
        # deprecated loses to current
        # provided beats default, deprecated or not
        winning_value = _find_winning_auth_value(p_opt, auth_params)
        if not winning_value:
            winning_value = _find_winning_auth_value(p_opt, config)

        # if the plugin tells us that this value is required
        # add it to the list of missing values so we can return a
        # complete list
        if not winning_value and p_opt.required:
            missing_required.append(p_opt)
            continue

        # Clean up after ourselves
        for opt in [p_opt.name] + [o.name for o in p_opt.deprecated_opts]:
            opt = opt.replace('-', '_')
            config.pop(opt, None)
            auth_params.pop(opt, None)

        if winning_value:
            # Prefer the plugin configuration dest value if the value's key
            # is marked as depreciated.
            if p_opt.dest is None:
                auth_params[p_opt.name.replace('-', '_')] = (
                    winning_value)
            else:
                auth_params[p_opt.dest] = winning_value

    if missing_required:
        raise exceptions.MissingRequiredParameters(
            plugin=auth_plugin, parameters=missing_required)

    return (config, auth_params)


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
