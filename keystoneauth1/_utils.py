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
import logging
import typing as ty

import iso8601


def get_logger(name: str) -> logging.Logger:
    name = name.replace(__name__.split('.')[0], 'keystoneauth')
    return logging.getLogger(name)


logger = get_logger(__name__)


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
    days: ty.Union[int, float] = 0,
    seconds: ty.Union[int, float] = 0,
    microseconds: ty.Union[int, float] = 0,
    milliseconds: ty.Union[int, float] = 0,
    minutes: ty.Union[int, float] = 0,
    hours: ty.Union[int, float] = 0,
    weeks: ty.Union[int, float] = 0,
) -> datetime.datetime:
    """Calculate the time in the future from utcnow.

    :param days: Days to add to timestamp.
    :param seconds: Seconds to add to timestamp.
    :param microseconds: Microseconds to add to timestamp.
    :param milliseconds: Milliseconds to add to timestamp.
    :param minutes: Minutes to add to timestamp.
    :param hours: Hours to add to timestamp.
    :param weeks: Weeks to add to timestamp.
    :returns:
        The time in the future based on ``timedelta_kwargs`` and in TZ-naive
        format.
    :rtype:
        datetime.datetime
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    delta = datetime.timedelta(
        days, seconds, microseconds, milliseconds, minutes, hours, weeks
    )
    return now + delta


def before_utcnow(
    days: ty.Union[int, float] = 0,
    seconds: ty.Union[int, float] = 0,
    microseconds: ty.Union[int, float] = 0,
    milliseconds: ty.Union[int, float] = 0,
    minutes: ty.Union[int, float] = 0,
    hours: ty.Union[int, float] = 0,
    weeks: ty.Union[int, float] = 0,
) -> datetime.datetime:
    r"""Calculate the time in the past from utcnow.

    :param days: Days to remove from timestamp.
    :param seconds: Seconds to remove from timestamp.
    :param microseconds: Microseconds to remove from timestamp.
    :param milliseconds: Milliseconds to remove from timestamp.
    :param minutes: Minutes to remove from timestamp.
    :param hours: Hours to remove from timestamp.
    :param weeks: Weeks to remove from timestamp.
    :returns:
        The time in the past based on ``timedelta_kwargs`` and in TZ-naive
        format.
    :rtype:
        datetime.datetime
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
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
