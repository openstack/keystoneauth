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

from keystoneauth.exceptions import base
from keystoneauth.i18n import _


class AuthPluginException(base.ClientException):
    """Something went wrong with auth plugins."""


class MissingAuthPlugin(AuthPluginException):
    """An authenticated request is required but no plugin available."""


class NoMatchingPlugin(AuthPluginException):
    """There were no auth plugins that could be created from the parameters
    provided.

    :param str name: The name of the plugin that was attempted to load.

    .. py:attribute:: name

        The name of the plugin that was attempted to load.
    """

    def __init__(self, name):
        self.name = name
        msg = _('The plugin %s could not be found') % name
        super(NoMatchingPlugin, self).__init__(msg)
