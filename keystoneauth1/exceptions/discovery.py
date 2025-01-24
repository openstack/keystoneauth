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

import os_service_types

from keystoneauth1.exceptions import base

_SERVICE_TYPES = os_service_types.ServiceTypes()


__all__ = (
    'DiscoveryFailure',
    'ImpliedVersionMismatch',
    'ImpliedMinVersionMismatch',
    'ImpliedMaxVersionMismatch',
    'VersionNotAvailable',
)

_PARSED_VERSION_T = tuple[ty.Union[int, float], ...]


class DiscoveryFailure(base.ClientException):
    message = "Discovery of client versions failed."


class VersionNotAvailable(DiscoveryFailure):
    message = "Discovery failed. Requested version is not available."


class ImpliedVersionMismatch(ValueError):
    label = 'version'

    def __init__(
        self, service_type: str, implied: _PARSED_VERSION_T, given: str
    ):
        super().__init__(
            f"service_type {service_type} was given which implies major API "
            f"version {str(implied[0])} but {self.label} of {given} was also "
            f"given. Please update your code to use the official service_type "
            f"{_SERVICE_TYPES.get_service_type(service_type)}."
        )


class ImpliedMinVersionMismatch(ImpliedVersionMismatch):
    label = 'min_version'


class ImpliedMaxVersionMismatch(ImpliedVersionMismatch):
    label = 'max_version'
