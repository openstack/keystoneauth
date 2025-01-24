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

from keystoneauth1.loading import _utils
from keystoneauth1.loading import base
from keystoneauth1 import session

if ty.TYPE_CHECKING:
    from oslo_config import cfg

    from keystoneauth1.loading import opts


__all__ = (
    'register_argparse_arguments',
    'load_from_argparse_arguments',
    'register_conf_options',
    'load_from_conf_options',
    'get_conf_options',
)


def _positive_non_zero_float(
    argument_value: ty.Optional[str],
) -> ty.Optional[float]:
    if argument_value is None:
        return None
    try:
        value = float(argument_value)
    except ValueError:
        msg = f"{argument_value} must be a float"
        raise argparse.ArgumentTypeError(msg)
    if value <= 0:
        msg = f"{argument_value} must be greater than 0"
        raise argparse.ArgumentTypeError(msg)
    return value


class Session(base._BaseLoader[session.Session]):
    @property
    def plugin_class(self) -> ty.Type[session.Session]:
        return session.Session

    def get_options(self) -> list['opts.Opt']:
        return []

    def load_from_options(
        self,
        insecure: bool = False,
        verify: ty.Union[bool, str, None] = None,
        cacert: ty.Optional[str] = None,
        cert: ty.Optional[str] = None,
        key: ty.Optional[str] = None,
        **kwargs: ty.Any,
    ) -> session.Session:
        """Create a session with individual certificate parameters.

        Some parameters used to create a session don't lend themselves to be
        loaded from config/CLI etc. Create a session by converting those
        parameters into session __init__ parameters.
        """
        if verify is None:
            if insecure:
                verify = False
            else:
                verify = cacert or True

        cert_: ty.Union[str, None, tuple[str, str]] = cert
        if cert and key:
            # passing cert and key together is deprecated in favour of the
            # requests lib form of having the cert and key as a tuple
            cert_ = (cert, key)

        return super().load_from_options(verify=verify, cert=cert_, **kwargs)

    def register_argparse_arguments(
        self, parser: argparse.ArgumentParser
    ) -> None:
        session_group = parser.add_argument_group(
            'API Connection Options',
            'Options controlling the HTTP API Connections',
        )

        session_group.add_argument(
            '--insecure',
            default=False,
            action='store_true',
            help='Explicitly allow client to perform '
            '"insecure" TLS (https) requests. The '
            'server\'s certificate will not be verified '
            'against any certificate authorities. This '
            'option should be used with caution.',
        )

        session_group.add_argument(
            '--os-cacert',
            metavar='<ca-certificate>',
            default=os.environ.get('OS_CACERT'),
            help='Specify a CA bundle file to use in '
            'verifying a TLS (https) server certificate. '
            'Defaults to env[OS_CACERT].',
        )

        session_group.add_argument(
            '--os-cert',
            metavar='<certificate>',
            default=os.environ.get('OS_CERT'),
            help='The location for the keystore (PEM formatted) '
            'containing the public key of this client. '
            'Defaults to env[OS_CERT].',
        )

        session_group.add_argument(
            '--os-key',
            metavar='<key>',
            default=os.environ.get('OS_KEY'),
            help='The location for the keystore (PEM formatted) '
            'containing the private key of this client. '
            'Defaults to env[OS_KEY].',
        )

        session_group.add_argument(
            '--timeout',
            default=600,
            type=_positive_non_zero_float,
            metavar='<seconds>',
            help='Set request timeout (in seconds).',
        )

        session_group.add_argument(
            '--collect-timing',
            default=False,
            action='store_true',
            help='Collect per-API call timing information.',
        )

    def load_from_argparse_arguments(
        self, namespace: argparse.Namespace, **kwargs: ty.Any
    ) -> session.Session:
        kwargs.setdefault('insecure', namespace.insecure)
        kwargs.setdefault('cacert', namespace.os_cacert)
        kwargs.setdefault('cert', namespace.os_cert)
        kwargs.setdefault('key', namespace.os_key)
        kwargs.setdefault('timeout', namespace.timeout)
        kwargs.setdefault('collect_timing', namespace.collect_timing)

        return self.load_from_options(**kwargs)

    def get_conf_options(
        self,
        deprecated_opts: ty.Optional[
            dict[str, list['cfg.DeprecatedOpt']]
        ] = None,
    ) -> list['cfg.Opt']:
        """Get oslo_config options that are needed for a :py:class:`.Session`.

        These may be useful without being registered for config file generation
        or to manipulate the options before registering them yourself.

        The options that are set are:
            :cafile: The certificate authority filename.
            :certfile: The client certificate file to present.
            :keyfile: The key for the client certificate.
            :insecure: Whether to ignore SSL verification.
            :timeout: The max time to wait for HTTP connections.
            :collect-timing: Whether to collect API timing information.
            :split-loggers: Whether to log requests to multiple loggers.

        :param dict deprecated_opts: Deprecated options that should be included
             in the definition of new options. This should be a dict from the
             name of the new option to a list of oslo.DeprecatedOpts that
             correspond to the new option. (optional)

             For example, to support the ``ca_file`` option pointing to the new
             ``cafile`` option name::

                 old_opt = oslo_cfg.DeprecatedOpt('ca_file', 'old_group')
                 deprecated_opts = {'cafile': [old_opt]}

        :returns: A list of oslo_config options.
        """
        cfg = _utils.get_oslo_config()

        if deprecated_opts is None:
            deprecated_opts = {}

        return [
            cfg.StrOpt(
                'cafile',
                deprecated_opts=deprecated_opts.get('cafile'),
                help='PEM encoded Certificate Authority to use '
                'when verifying HTTPs connections.',
            ),
            cfg.StrOpt(
                'certfile',
                deprecated_opts=deprecated_opts.get('certfile'),
                help='PEM encoded client certificate cert file',
            ),
            cfg.StrOpt(
                'keyfile',
                deprecated_opts=deprecated_opts.get('keyfile'),
                help='PEM encoded client certificate key file',
            ),
            cfg.BoolOpt(
                'insecure',
                default=False,
                deprecated_opts=deprecated_opts.get('insecure'),
                help='Verify HTTPS connections.',
            ),
            cfg.IntOpt(
                'timeout',
                deprecated_opts=deprecated_opts.get('timeout'),
                help='Timeout value for http requests',
            ),
            cfg.BoolOpt(
                'collect-timing',
                deprecated_opts=deprecated_opts.get('collect-timing'),
                default=False,
                help='Collect per-API call timing information.',
            ),
            cfg.BoolOpt(
                'split-loggers',
                deprecated_opts=deprecated_opts.get('split-loggers'),
                default=False,
                help='Log requests to multiple loggers.',
            ),
        ]

    def register_conf_options(
        self,
        conf: 'cfg.ConfigOpts',
        group: str,
        deprecated_opts: ty.Optional[
            dict[str, list['cfg.DeprecatedOpt']]
        ] = None,
    ) -> list['cfg.Opt']:
        """Register the oslo_config options that are needed for a session.

        The options that are set are:
            :cafile: The certificate authority filename.
            :certfile: The client certificate file to present.
            :keyfile: The key for the client certificate.
            :insecure: Whether to ignore SSL verification.
            :timeout: The max time to wait for HTTP connections.
            :collect-timing: Whether to collect API timing information.
            :split-loggers: Whether to log requests to multiple loggers.

        :param oslo_config.Cfg conf: config object to register with.
        :param string group: The ini group to register options in.
        :param dict deprecated_opts: Deprecated options that should be included
             in the definition of new options. This should be a dict from the
             name of the new option to a list of oslo.DeprecatedOpts that
             correspond to the new option. (optional)

             For example, to support the ``ca_file`` option pointing to the new
             ``cafile`` option name::

                 old_opt = oslo_cfg.DeprecatedOpt('ca_file', 'old_group')
                 deprecated_opts = {'cafile': [old_opt]}

        :returns: The list of options that was registered.
        """
        opts = self.get_conf_options(deprecated_opts=deprecated_opts)
        conf.register_group(_utils.get_oslo_config().OptGroup(group))
        conf.register_opts(opts, group=group)
        return opts

    def load_from_conf_options(
        self, conf: 'cfg.ConfigOpts', group: str, **kwargs: ty.Any
    ) -> session.Session:
        """Create a session object from an oslo_config object.

        The options must have been previously registered with
        register_conf_options.

        :param oslo_config.Cfg conf: config object to register with.
        :param string group: The ini group to register options in.
        :param dict kwargs: Additional parameters to pass to session
                            construction.
        :returns: A new session object.
        :rtype: :py:class:`.Session`
        """
        c = conf[group]

        kwargs.setdefault('insecure', c.insecure)
        kwargs.setdefault('cacert', c.cafile)
        kwargs.setdefault('cert', c.certfile)
        kwargs.setdefault('key', c.keyfile)
        kwargs.setdefault('timeout', c.timeout)
        kwargs.setdefault('collect_timing', c.collect_timing)
        kwargs.setdefault('split_loggers', c.split_loggers)

        return self.load_from_options(**kwargs)


def register_argparse_arguments(parser: argparse.ArgumentParser) -> None:
    Session().register_argparse_arguments(parser)


def load_from_argparse_arguments(
    namespace: argparse.Namespace, **kwargs: ty.Any
) -> session.Session:
    return Session().load_from_argparse_arguments(namespace, **kwargs)


def register_conf_options(
    conf: 'cfg.ConfigOpts',
    group: str,
    deprecated_opts: ty.Optional[dict[str, list['cfg.DeprecatedOpt']]] = None,
) -> list['cfg.Opt']:
    return Session().register_conf_options(
        conf, group, deprecated_opts=deprecated_opts
    )


def load_from_conf_options(
    conf: 'cfg.ConfigOpts', group: str, **kwargs: ty.Any
) -> session.Session:
    return Session().load_from_conf_options(conf, group, **kwargs)


def get_conf_options(
    deprecated_opts: ty.Optional[dict[str, list['cfg.DeprecatedOpt']]] = None,
) -> list['cfg.Opt']:
    return Session().get_conf_options(deprecated_opts=deprecated_opts)
