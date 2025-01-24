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

import typing as ty

from keystoneauth1.loading import base
from keystoneauth1.loading import opts
import keystoneauth1.plugin

if ty.TYPE_CHECKING:
    from oslo_config import cfg


_AUTH_TYPE_OPT = opts.Opt(
    'auth_type',
    deprecated=[opts.Opt('auth_plugin')],
    help='Authentication type to load',
)

_section_help = 'Config Section from which to load plugin specific options'
_AUTH_SECTION_OPT = opts.Opt('auth_section', help=_section_help)


__all__ = (
    'get_common_conf_options',
    'get_plugin_conf_options',
    'register_conf_options',
    'load_from_conf_options',
)


def get_common_conf_options() -> list['cfg.Opt']:
    """Get the oslo_config options common for all auth plugins.

    These may be useful without being registered for config file generation
    or to manipulate the options before registering them yourself.

    The options that are set are:
        :auth_type: The name of the plugin to load.
        :auth_section: The config file section to load options from.

    :returns: A list of oslo_config options.
    """
    return [_AUTH_TYPE_OPT._to_oslo_opt(), _AUTH_SECTION_OPT._to_oslo_opt()]


def get_plugin_conf_options(
    plugin: ty.Union[
        base.BaseLoader[keystoneauth1.plugin.BaseAuthPluginT], str
    ],
) -> list['cfg.Opt']:
    """Get the oslo_config options for a specific plugin.

    This will be the list of config options that is registered and loaded by
    the specified plugin.

    :param plugin: The name of the plugin loader or a plugin loader object
    :type plugin: str or keystoneauth1.loading.BaseLoader

    :returns: A list of oslo_config options.
    """
    if isinstance(plugin, str):
        opts = base.get_plugin_options(plugin)
    else:
        opts = plugin.get_options()

    return [o._to_oslo_opt() for o in opts]


def register_conf_options(conf: 'cfg.ConfigOpts', group: str) -> None:
    """Register the oslo_config options that are needed for a plugin.

    This only registers the basic options shared by all plugins. Options that
    are specific to a plugin are loaded just before they are read.

    The defined options are:

     - auth_type: the name of the auth plugin that will be used for
         authentication.
     - auth_section: the group from which further auth plugin options should be
         taken. If section is not provided then the auth plugin options will be
         taken from the same group as provided in the parameters.

    :param conf: config object to register with.
    :type conf: oslo_config.cfg.ConfigOpts
    :param string group: The ini group to register options in.
    """
    conf.register_opt(_AUTH_SECTION_OPT._to_oslo_opt(), group=group)

    # NOTE(jamielennox): plugins are allowed to specify a 'section' which is
    # the group that auth options should be taken from. If not present they
    # come from the same as the base options were registered in. If present
    # then the auth_plugin option may be read from that section so add that
    # option.
    if conf[group].auth_section:
        group = conf[group].auth_section

    conf.register_opt(_AUTH_TYPE_OPT._to_oslo_opt(), group=group)


def load_from_conf_options(
    conf: 'cfg.ConfigOpts', group: str, **kwargs: ty.Any
) -> ty.Optional['keystoneauth1.plugin.BaseAuthPlugin']:
    """Load a plugin from an oslo_config CONF object.

    Each plugin will register their own required options and so there is no
    standard list and the plugin should be consulted.

    The base options should have been registered with register_conf_options
    before this function is called.

    :param conf: A conf object.
    :type conf: oslo_config.cfg.ConfigOpts
    :param str group: The group name that options should be read from.

    :returns: An authentication Plugin or None if a name is not provided
    :rtype: :class:`keystoneauth1.plugin.BaseAuthPlugin`

    :raises keystoneauth1.exceptions.auth_plugins.NoMatchingPlugin:
        if a plugin cannot be created.
    """
    # NOTE(jamielennox): plugins are allowed to specify a 'section' which is
    # the group that auth options should be taken from. If not present they
    # come from the same as the base options were registered in.
    if conf[group].auth_section:
        group = conf[group].auth_section

    name = conf[group].auth_type
    if not name:
        return None

    loader: base.BaseLoader[keystoneauth1.plugin.BaseAuthPlugin] = (
        base.get_plugin_loader(name)
    )
    loader_opts = loader.get_options()
    oslo_opts = [o._to_oslo_opt() for o in loader_opts]

    conf.register_opts(oslo_opts, group=group)

    def _getter(opt: opts.Opt) -> ty.Any:
        return conf[group][opt.dest]

    return loader.load_from_options_getter(_getter, **kwargs)
