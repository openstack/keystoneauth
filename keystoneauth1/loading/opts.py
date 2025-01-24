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

import itertools
import os
import typing as ty

from keystoneauth1.loading import _utils

if ty.TYPE_CHECKING:
    from oslo_config import cfg

__all__ = ('Opt',)


class Opt:
    """An option required by an authentication plugin.

    Opts provide a means for authentication plugins that are going to be
    dynamically loaded to specify the parameters that are to be passed to the
    plugin on initialization.

    The Opt specifies information about the way the plugin parameter is to be
    represented in different loading mechanisms.

    When defining an Opt with a - the - should be present in the name
    parameter. This will automatically be converted to an _ when passing to the
    plugin initialization. For example, you should specify::

        Opt('user-domain-id')

    which will pass the value as `user_domain_id` to the plugin's
    initialization.

    :param str name: The name of the option.
    :param callable type: The type of the option. This is a callable which is
        passed the raw option that was loaded (often a string) and is required
        to return the parameter in the type expected by __init__.
    :param str help: The help text that is shown along with the option.
    :param bool secret: If the parameter is secret it should not be printed or
        logged in debug output.
    :param str dest: the name of the argument that will be passed to __init__.
        This allows you to have a different name in loading than is used by the
        __init__ function. Defaults to the value of name.
    :param keystoneauth1.loading.Opt deprecated: A list of other options that
        are deprecated in favour of this one. This ensures the old options are
        still registered.
    :type opt: list(Opt)
    :param default: A default value that can be used if one is not provided.
    :param str metavar: The <metavar> that should be printed in CLI help text.
    :param bool required: If the option is required to load the plugin. If a
        required option is not present loading should fail.
    :param str prompt: If the option can be requested via a prompt (where
        appropriate) set the string that should be used to prompt with.
    """

    def __init__(
        self,
        name: str,
        type: ty.Type[ty.Any] = str,
        help: ty.Optional[str] = None,
        secret: bool = False,
        dest: ty.Optional[str] = None,
        deprecated: ty.Optional[list['Opt']] = None,
        default: ty.Any = None,
        metavar: ty.Optional[str] = None,
        required: bool = False,
        prompt: ty.Optional[str] = None,
    ):
        if not callable(type):
            raise TypeError('type must be callable')

        if dest is None:
            dest = name.replace('-', '_')

        self.name = name
        self.type = type
        self.help = help
        self.secret = secret
        self.required = required
        self.dest = dest
        self.deprecated = [] if deprecated is None else deprecated
        self.default = default
        self.metavar = metavar
        self.prompt = prompt
        # These are for oslo.config compat
        self.deprecated_opts = self.deprecated
        self.deprecated_for_removal = False
        self.sample_default = None
        self.group = None

    def __repr__(self) -> str:
        """Return string representation of option name."""
        return f'<Opt: {self.name}>'

    def _to_oslo_opt(self) -> 'cfg.Opt':
        cfg = _utils.get_oslo_config()
        deprecated_opts = [cfg.DeprecatedOpt(o.name) for o in self.deprecated]

        return cfg.Opt(
            name=self.name,
            type=self.type,
            help=self.help,
            secret=self.secret,
            required=self.required,
            dest=self.dest,
            deprecated_opts=deprecated_opts,
            metavar=self.metavar,
        )

    def __eq__(self, other: ty.Any) -> bool:
        """Define equality operator on option parameters."""
        return (
            type(self) is type(other)
            and self.name == other.name
            and self.type == other.type
            and self.help == other.help
            and self.secret == other.secret
            and self.required == other.required
            and self.dest == other.dest
            and self.deprecated == other.deprecated
            and self.default == other.default
            and self.metavar == other.metavar
        )

    @property
    def _all_opts(self) -> itertools.chain['Opt']:
        return itertools.chain([self], self.deprecated)

    @property
    def argparse_args(self) -> list[str]:
        return [f'--os-{o.name}' for o in self._all_opts]

    @property
    def argparse_envvars(self) -> ty.List[str]:
        return [
            'OS_{}'.format(o.name.replace('-', '_').upper())
            for o in self._all_opts
        ]

    @property
    def argparse_default(self) -> ty.Any:
        # select the first ENV that is not false-y or return None
        for envvar in self.argparse_envvars:
            v = os.environ.get(envvar)
            if v:
                return v

        return self.default
