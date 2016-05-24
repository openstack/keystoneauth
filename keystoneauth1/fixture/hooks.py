# Copyright (c) 2016 Hewlett-Packard Enterprise Development Company, L.P.
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
"""Custom hooks for betamax and keystoneauth.

   Module providing a set of hooks specially designed for
   interacting with clouds and keystone authentication.

:author: Yolanda Robla
"""

import re


def mask_credentials(content):
    """it will mask all credentials for a given content."""
    content = re.sub(r'"tenantName": "(.*?)"',
                     '"tenantName": "dummy"', content)
    content = re.sub(r'"username": "(.*?)"',
                     '"username": "dummy"', content)
    content = re.sub(r'"password": "(.*?)"',
                     '"password": "********"', content)
    return content


def update_expiration(content):
    """it will set token expiration in the long future."""
    content = re.sub(r'"expires": "(.*?)"',
                     '"expires": "9999-12-31T23:59:59Z"', content)
    return content


def pre_record_hook(interaction, cassette):
    """Hook to mask saved data.

    This hook will be triggered before saving the interaction, and
    will perform two tasks:
    - mask user, project and password in the saved data
    - set token expiration time to an inifinite time.
    """
    request_body = interaction.data['request']['body']
    request_body['string'] = mask_credentials(
        request_body['string'])
    response_body = interaction.data['response']['body']
    response_body['string'] = update_expiration(mask_credentials(
        response_body['string']))
