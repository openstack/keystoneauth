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
    def get_conf_options():
        """Get oslo_config options that are needed for a :py:class:`.Adapter`.

        These may be useful without being registered for config file generation
        or to manipulate the options before registering them yourself.

        The options that are set are:
            :service_type:      The default service_type for URL discovery.
            :service_name:      The default service_name for URL discovery.
            :interface:         The default interface for URL discovery.
            :region_name:       The default region_name for URL discovery.
            :endpoint_override: Always use this endpoint URL for requests
                                for this client.

        :returns: A list of oslo_config options.
        """
        cfg = _utils.get_oslo_config()

        return [cfg.StrOpt('service-type',
                           help='The default service_type for endpoint URL '
                                'discovery.'),
                cfg.StrOpt('service-name',
                           help='The default service_name for endpoint URL '
                                'discovery.'),
                cfg.StrOpt('interface',
                           help='The default interface for endpoint URL '
                                'discovery.'),
                cfg.StrOpt('region-name',
                           help='The default region_name for endpoint URL '
                                'discovery.'),
                cfg.StrOpt('endpoint-override',
                           help='Always use this endpoint URL for requests '
                                'for this client.'),
                ]

    def register_conf_options(self, conf, group):
        """Register the oslo_config options that are needed for an Adapter.

        The options that are set are:
            :service_type:      The default service_type for URL discovery.
            :service_name:      The default service_name for URL discovery.
            :interface:         The default interface for URL discovery.
            :region_name:       The default region_name for URL discovery.
            :endpoint_override: Always use this endpoint URL for requests
                                for this client.

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

        kwargs.setdefault('service_type', c.service_type)
        kwargs.setdefault('service_name', c.service_name)
        kwargs.setdefault('interface', c.interface)
        kwargs.setdefault('region_name', c.region_name)
        kwargs.setdefault('endpoint_override', c.endpoint_override)

        return self.load_from_options(**kwargs)


def register_argparse_arguments(*args, **kwargs):
    return adapter.register_adapter_argparse_arguments(*args, **kwargs)


def register_service_argparse_arguments(*args, **kwargs):
    return adapter.register_service_adapter_argparse_arguments(*args, **kwargs)


def register_conf_options(*args, **kwargs):
    return Adapter().register_conf_options(*args, **kwargs)


def load_from_conf_options(*args, **kwargs):
    return Adapter().load_from_conf_options(*args, **kwargs)


def get_conf_options():
    return Adapter.get_conf_options()
