# Copyright 2014 IBM Corp.
#
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

"""oslo.i18n integration stub.

This module is a stub to allow dropping the use of oslo.i18n without
requiring a change to all of the various strings throughout keystoneauth.
"""

# TODO(morganfainberg): Eliminate the use of translation functions around
# each string in the keystoneauth library and then remove this file.

_ = lambda x: x
_LI = _
_LW = _
_LE = _
_LC = _
