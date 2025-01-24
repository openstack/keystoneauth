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

import argparse
import os
import typing as ty

from keystoneauth1.loading import base

if ty.TYPE_CHECKING:
    from keystoneauth1.loading import opts
    from keystoneauth1 import plugin


__all__ = ('register_argparse_arguments', 'load_from_argparse_arguments')


def _register_plugin_argparse_arguments(
    parser: ty.Union[argparse.ArgumentParser, argparse._ArgumentGroup],
    plugin: base.BaseLoader['plugin.BaseAuthPluginT'],
) -> None:
    for opt in plugin.get_options():
        parser.add_argument(
            *opt.argparse_args,
            default=opt.argparse_default,
            metavar=opt.metavar,
            help=opt.help,
            dest=f'os_{opt.dest}',
        )


def register_argparse_arguments(
    parser: argparse.ArgumentParser, argv: list[str], default: ty.Any = None
) -> ty.Optional[base.BaseLoader['plugin.BaseAuthPluginT']]:
    """Register CLI options needed to create a plugin.

    The function inspects the provided arguments so that it can also register
    the options required for that specific plugin if available.

    :param parser: the parser to attach argparse options to.
    :type parser: argparse.ArgumentParser
    :param list argv: the arguments provided to the appliation.
    :param str/class default: a default plugin name or a plugin object to use
                              if one isn't specified by the CLI. default: None.

    :returns: The plugin class that will be loaded or None if not provided.
    :rtype: :class:`keystoneauth1.loader.BaseLoader`

    :raises keystoneauth1.exceptions.auth_plugins.NoMatchingPlugin:
        if a plugin cannot be created.
    """
    in_parser = argparse.ArgumentParser(add_help=False)
    env_plugin = os.environ.get(
        'OS_AUTH_TYPE', os.environ.get('OS_AUTH_PLUGIN', default)
    )
    for p in (in_parser, parser):
        p.add_argument(
            '--os-auth-type',
            '--os-auth-plugin',
            metavar='<name>',
            default=env_plugin,
            help='Authentication type to use',
        )

    options, _args = in_parser.parse_known_args(argv)

    if not options.os_auth_type:
        return None

    if isinstance(options.os_auth_type, base.BaseLoader):
        msg = 'Default Authentication options'
        plugin = options.os_auth_type
    else:
        msg = f'Options specific to the {options.os_auth_type} plugin.'
        plugin = base.get_plugin_loader(options.os_auth_type)

    group = parser.add_argument_group('Authentication Options', msg)
    _register_plugin_argparse_arguments(group, plugin)
    return plugin


def load_from_argparse_arguments(
    namespace: argparse.Namespace, **kwargs: ty.Any
) -> ty.Optional['plugin.BaseAuthPluginT']:
    """Retrieve the created plugin from the completed argparse results.

    Loads and creates the auth plugin from the information parsed from the
    command line by argparse.

    :param Namespace namespace: The result from CLI parsing.

    :returns: An auth plugin, or None if a name is not provided.
    :rtype: :class:`keystoneauth1.plugin.BaseAuthPlugin`

    :raises keystoneauth1.exceptions.auth_plugins.NoMatchingPlugin:
        if a plugin cannot be created.
    """
    os_auth_type = namespace.os_auth_type

    if not os_auth_type:
        return None

    loader: base.BaseLoader[plugin.BaseAuthPluginT]
    if isinstance(os_auth_type, base.BaseLoader):
        loader = os_auth_type
    else:
        loader = base.get_plugin_loader(os_auth_type)

    def _getter(opt: 'opts.Opt') -> ty.Any:
        return getattr(namespace, f'os_{opt.dest}')

    return loader.load_from_options_getter(_getter, **kwargs)
