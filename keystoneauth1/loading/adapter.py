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

from keystoneauth1 import adapter
from keystoneauth1.loading import _utils
from keystoneauth1.loading import base


__all__ = ('register_argparse_arguments',
           'register_service_argparse_arguments',
           'register_conf_options',
           'load_from_conf_options',
           'get_conf_options')


class Adapter(base.BaseLoader):

    @property
    def plugin_class(self):
        return adapter.Adapter

    def get_options(self):
        return []

    @staticmethod
    def get_conf_options(include_deprecated=True):
        """Get oslo_config options that are needed for a :py:class:`.Adapter`.

        These may be useful without being registered for config file generation
        or to manipulate the options before registering them yourself.

        The options that are set are:
            :service_type:      The default service_type for URL discovery.
            :service_name:      The default service_name for URL discovery.
            :interface:         The default interface for URL discovery.
                                (deprecated)
            :valid_interfaces:  List of acceptable interfaces for URL
                                discovery. Can be a list of any of
                                'public', 'internal' or 'admin'.
            :region_name:       The default region_name for URL discovery.
            :endpoint_override: Always use this endpoint URL for requests
                                for this client.
            :version:           The minimum version restricted to a given Major
                                API. Mutually exclusive with min_version and
                                max_version.
            :min_version:       The minimum major version of a given API,
                                intended to be used as the lower bound of a
                                range with max_version. Mutually exclusive with
                                version. If min_version is given with no
                                max_version it is as if max version is
                                'latest'.
            :max_version:       The maximum major version of a given API,
                                intended to be used as the upper bound of a
                                range with min_version. Mutually exclusive with
                                version.

        :param include_deprecated: If True (the default, for backward
                                   compatibility), deprecated options are
                                   included in the result.  If False, they are
                                   excluded.
        :returns: A list of oslo_config options.
        """
        cfg = _utils.get_oslo_config()

        opts = [cfg.StrOpt('service-type',
                           help='The default service_type for endpoint URL '
                                'discovery.'),
                cfg.StrOpt('service-name',
                           help='The default service_name for endpoint URL '
                                'discovery.'),
                cfg.ListOpt('valid-interfaces',
                            help='List of interfaces, in order of preference, '
                                 'for endpoint URL.'),
                cfg.StrOpt('region-name',
                           help='The default region_name for endpoint URL '
                                'discovery.'),
                cfg.StrOpt('endpoint-override',
                           help='Always use this endpoint URL for requests '
                                'for this client.'),
                cfg.StrOpt('version',
                           help='Minimum Major API version within a given '
                                'Major API version for endpoint URL '
                                'discovery. Mutually exclusive with '
                                'min_version and max_version'),
                cfg.StrOpt('min-version',
                           help='The minimum major version of a given API, '
                                'intended to be used as the lower bound of a '
                                'range with max_version. Mutually exclusive '
                                'with version. If min_version is given with '
                                'no max_version it is as if max version is '
                                '"latest".'),
                cfg.StrOpt('max-version',
                           help='The maximum major version of a given API, '
                                'intended to be used as the upper bound of a '
                                'range with min_version. Mutually exclusive '
                                'with version.'),
                ]
        if include_deprecated:
            opts += [
                cfg.StrOpt('interface',
                           help='The default interface for endpoint URL '
                                'discovery.',
                           deprecated_for_removal=True,
                           deprecated_reason='Using valid-interfaces is'
                                             ' preferrable because it is'
                                             ' capable of accepting a list of'
                                             ' possible interfaces.'),
            ]
        return opts

    def register_conf_options(self, conf, group):
        """Register the oslo_config options that are needed for an Adapter.

        The options that are set are:
            :service_type:      The default service_type for URL discovery.
            :service_name:      The default service_name for URL discovery.
            :interface:         The default interface for URL discovery.
                                (deprecated)
            :valid_interfaces:  List of acceptable interfaces for URL
                                discovery. Can be a list of any of
                                'public', 'internal' or 'admin'.
            :region_name:       The default region_name for URL discovery.
            :endpoint_override: Always use this endpoint URL for requests
                                for this client.
            :version:           The minimum version restricted to a given Major
                                API. Mutually exclusive with min_version and
                                max_version.
            :min_version:       The minimum major version of a given API,
                                intended to be used as the lower bound of a
                                range with max_version. Mutually exclusive with
                                version. If min_version is given with no
                                max_version it is as if max version is
                                'latest'.
            :max_version:       The maximum major version of a given API,
                                intended to be used as the upper bound of a
                                range with min_version. Mutually exclusive with
                                version.

        :param oslo_config.Cfg conf: config object to register with.
        :param string group: The ini group to register options in.
        :returns: The list of options that was registered.
        """
        opts = self.get_conf_options()
        conf.register_group(_utils.get_oslo_config().OptGroup(group))
        conf.register_opts(opts, group=group)
        return opts

    def load_from_conf_options(self, conf, group, **kwargs):
        """Create an Adapter object from an oslo_config object.

        The options must have been previously registered with
        register_conf_options.

        :param oslo_config.Cfg conf: config object to register with.
        :param string group: The ini group to register options in.
        :param dict kwargs: Additional parameters to pass to Adapter
                            construction.
        :returns: A new Adapter object.
        :rtype: :py:class:`.Adapter`
        """
        c = conf[group]

        if c.valid_interfaces and c.interface:
            raise TypeError("interface and valid_interfaces are mutually"
                            " exclusive. Please use valid_interfaces.")
        if c.valid_interfaces:
            for iface in c.valid_interfaces:
                if iface not in ('public', 'internal', 'admin'):
                    raise TypeError("'{iface}' is not a valid value for"
                                    " valid_interfaces. Valid valies are"
                                    " public, internal or admin".format(
                                        iface=iface))
            kwargs.setdefault('interface', c.valid_interfaces)
        else:
            kwargs.setdefault('interface', c.interface)
        kwargs.setdefault('service_type', c.service_type)
        kwargs.setdefault('service_name', c.service_name)
        kwargs.setdefault('region_name', c.region_name)
        kwargs.setdefault('endpoint_override', c.endpoint_override)
        kwargs.setdefault('version', c.version)
        kwargs.setdefault('min_version', c.min_version)
        kwargs.setdefault('max_version', c.max_version)
        if kwargs['version'] and (
                kwargs['max_version'] or kwargs['min_version']):
            raise TypeError(
                "version is mutually exclusive with min_version and"
                " max_version")

        return self.load_from_options(**kwargs)


def register_argparse_arguments(*args, **kwargs):
    return adapter.register_adapter_argparse_arguments(*args, **kwargs)


def register_service_argparse_arguments(*args, **kwargs):
    return adapter.register_service_adapter_argparse_arguments(*args, **kwargs)


def register_conf_options(*args, **kwargs):
    return Adapter().register_conf_options(*args, **kwargs)


def load_from_conf_options(*args, **kwargs):
    return Adapter().load_from_conf_options(*args, **kwargs)


def get_conf_options(*args, **kwargs):
    return Adapter.get_conf_options(*args, **kwargs)
