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

from oslo_config import cfg

from keystoneauth1 import loading
from keystoneauth1 import token_endpoint


class TokenEndpoint(loading.BaseLoader):

    @property
    def plugin_class(self):
        return token_endpoint.TokenEndpoint

    def get_options(self):
        options = super(TokenEndpoint, self).get_options()

        options.extend([
            cfg.StrOpt('endpoint',
                       help='The endpoint that will always be used'),
            cfg.StrOpt('token',
                       secret=True,
                       help='The token that will always be used'),
        ])

        return options
