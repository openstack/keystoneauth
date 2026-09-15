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

import datetime
import json
import logging
from typing import Any

import iso8601

# Substrings matched case-insensitively against dict keys when masking
# structured data for debug logs. Same idea as identity/v3/oidc.py.
_SENSITIVE_KEY_MARKERS = (
    'password',
    'passphrase',
    'secret',
    'credential',
    'token',
    'code',
)

REDACTED_VALUE = '***'


def get_logger(name: str) -> logging.Logger:
    name = name.replace(__name__.split('.')[0], 'keystoneauth')
    return logging.getLogger(name)


logger = get_logger(__name__)


def _is_sensitive_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    key_lower = key.lower()
    return any(marker in key_lower for marker in _SENSITIVE_KEY_MARKERS)


def mask_sensitive_data(data: Any) -> Any:
    """Return a copy of structured data with sensitive values redacted."""
    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if _is_sensitive_key(key):
                masked[key] = REDACTED_VALUE
            else:
                masked[key] = mask_sensitive_data(value)
        return masked
    if isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data


def mask_sensitive_string(data: str) -> str:
    """Redact sensitive JSON values in a string for debug logging."""
    try:
        parsed = json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return data
    if not isinstance(parsed, (dict, list)):
        return data
    return json.dumps(mask_sensitive_data(parsed))


def normalize_time(timestamp: datetime.datetime) -> datetime.datetime:
    """Normalize time in arbitrary timezone to UTC naive object."""
    offset = timestamp.utcoffset()
    if offset is None:
        return timestamp
    return timestamp.replace(tzinfo=None) - offset


def parse_isotime(timestr: str) -> datetime.datetime:
    """Parse time from ISO 8601 format."""
    try:
        return iso8601.parse_date(timestr)
    except iso8601.ParseError as e:
        raise ValueError(str(e))
    except TypeError as e:
        raise ValueError(str(e))


def from_utcnow(
    days: int | float = 0,
    seconds: int | float = 0,
    microseconds: int | float = 0,
    milliseconds: int | float = 0,
    minutes: int | float = 0,
    hours: int | float = 0,
    weeks: int | float = 0,
) -> datetime.datetime:
    """Calculate the time in the future from utcnow.

    :param days: Days to add to timestamp.
    :param seconds: Seconds to add to timestamp.
    :param microseconds: Microseconds to add to timestamp.
    :param milliseconds: Milliseconds to add to timestamp.
    :param minutes: Minutes to add to timestamp.
    :param hours: Hours to add to timestamp.
    :param weeks: Weeks to add to timestamp.
    :returns: The time in the future based on ``timedelta_kwargs`` and in
        TZ-naive format.
    """
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    delta = datetime.timedelta(
        days, seconds, microseconds, milliseconds, minutes, hours, weeks
    )
    return now + delta


def before_utcnow(
    days: int | float = 0,
    seconds: int | float = 0,
    microseconds: int | float = 0,
    milliseconds: int | float = 0,
    minutes: int | float = 0,
    hours: int | float = 0,
    weeks: int | float = 0,
) -> datetime.datetime:
    r"""Calculate the time in the past from utcnow.

    :param days: Days to remove from timestamp.
    :param seconds: Seconds to remove from timestamp.
    :param microseconds: Microseconds to remove from timestamp.
    :param milliseconds: Milliseconds to remove from timestamp.
    :param minutes: Minutes to remove from timestamp.
    :param hours: Hours to remove from timestamp.
    :param weeks: Weeks to remove from timestamp.
    :returns: The time in the past based on ``timedelta_kwargs`` and in
        TZ-naive format.
    """
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    delta = datetime.timedelta(
        days, seconds, microseconds, milliseconds, minutes, hours, weeks
    )
    return now - delta


# Detect if running on the Windows Subsystem for Linux
try:
    with open('/proc/version') as f:
        is_windows_linux_subsystem = 'microsoft' in f.read().lower()
except OSError:
    is_windows_linux_subsystem = False
