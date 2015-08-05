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

try:
    from oslo_config import cfg
except ImportError:
    cfg = None

from keystoneauth1 import _utils as utils


class Opt(object):

    @utils.positional()
    def __init__(self,
                 name,
                 type=str,
                 help=None,
                 secret=False,
                 dest=None,
                 deprecated=None,
                 default=None,
                 metavar=None):
        if not callable(type):
            raise TypeError('type must be callable')

        if dest is None:
            dest = name.replace('-', '_')

        self.name = name
        self.type = type
        self.help = help
        self.secret = secret
        self.dest = dest
        self.deprecated = [] if deprecated is None else deprecated
        self.default = default
        self.metavar = metavar

    def __repr__(self):
        return '<Opt: %s>' % self.name

    def _to_oslo_opt(self):
        if not cfg:
            raise ImportError("oslo.config is not an automatic dependency of "
                              "keystoneauth. If you wish to use oslo.config "
                              "you need to import it into your application's "
                              "requirements file. ")

        deprecated_opts = [o._to_oslo_opt() for o in self.deprecated]

        return cfg.Opt(name=self.name,
                       type=self.type,
                       help=self.help,
                       secret=self.secret,
                       dest=self.dest,
                       deprecated_opts=deprecated_opts,
                       metavar=self.metavar)

    @property
    def _all_opts(self):
        return itertools.chain([self], self.deprecated)

    @property
    def argparse_args(self):
        return ['--os-%s' % o.name for o in self._all_opts]

    @property
    def argparse_default(self):
        # select the first ENV that is not false-y or return None
        for o in self._all_opts:
            v = os.environ.get('OS_%s' % self.name.replace('-', '_').upper())
            if v:
                return v

        return self.default
