#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

UNSCOPED_TOKEN = {
    "token": {
        "issued_at": "2014-06-09T09:48:59.643406Z",
        "extras": {},
        "methods": ["oidc"],
        "expires_at": "2014-06-09T10:48:59.643375Z",
        "user": {
            "OS-FEDERATION": {
                "identity_provider": {
                    "id": "bluepages"
                },
                "protocol": {
                    "id": "oidc"
                },
                "groups": [
                    {"id": "1764fa5cf69a49a4918131de5ce4af9a"}
                ]
            },
            "id": "oidc_user%40example.com",
            "name": "oidc_user@example.com"
        }
    }
}

ACCESS_TOKEN_VIA_PASSWORD_RESP = {
    "access_token": "z5H1ITZLlJVDHQXqJun",
    "token_type": "bearer",
    "expires_in": 3599,
    "scope": "profile",
    "refresh_token": "DCERsh83IAhu9bhavrp"
}

ACCESS_TOKEN_VIA_AUTH_GRANT_RESP = {
    "access_token": "ya29.jgGIjfVrBPWLStWSU3eh8ioE6hG06QQ",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "1/ySXNO9XISBMIgOrJDtdun6zK6XiATCKT",
    "id_token": "eyJhbGciOiJSUzI1Ni8hOYHuZT8dt_yynmJVhcU"
}
