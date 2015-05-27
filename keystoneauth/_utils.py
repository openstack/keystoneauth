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
import functools
import inspect
import logging

import iso8601
import six


logger = logging.getLogger(__name__)


class positional(object):
    """A decorator which enforces only some args may be passed positionally.

    This idea and some of the code was taken from the oauth2 client of the
    google-api client.

    This decorator makes it easy to support Python 3 style key-word only
    parameters. For example, in Python 3 it is possible to write::

      def fn(pos1, *, kwonly1, kwonly2=None):
          ...

    All named parameters after * must be a keyword::

      fn(10, 'kw1', 'kw2')  # Raises exception.
      fn(10, kwonly1='kw1', kwonly2='kw2')  # Ok.

    To replicate this behaviour with the positional decorator you simply
    specify how many arguments may be passed positionally. To replicate the
    example above::

        @positional(1)
        def fn(pos1, kwonly1=None, kwonly2=None):
            ...

    If no default value is provided to a keyword argument, it becomes a
    required keyword argument::

        @positional(0)
        def fn(required_kw):
            ...

    This must be called with the keyword parameter::

        fn()  # Raises exception.
        fn(10)  # Raises exception.
        fn(required_kw=10)  # Ok.

    When defining instance or class methods always remember that in python the
    first positional argument passed is always the instance so you will need to
    account for `self` and `cls`::

        class MyClass(object):

            @positional(2)
            def my_method(self, pos1, kwonly1=None):
                ...

            @classmethod
            @positional(2)
            def my_method(cls, pos1, kwonly1=None):
                ...

    If you would prefer not to account for `self` and `cls` you can use the
    `method` and `classmethod` helpers which do not consider the initial
    positional argument. So the following class is exactly the same as the one
    above::

        class MyClass(object):

            @positional.method(1)
            def my_method(self, pos1, kwonly1=None):
                ...

            @positional.classmethod(1)
            def my_method(cls, pos1, kwonly1=None):
                ...

    If a value isn't provided to the decorator then it will enforce that
    every variable without a default value will be required to be a kwarg::

        @positional()
        def fn(pos1, kwonly1=None):
            ...

        fn(10)  # Ok.
        fn(10, 20)  # Raises exception.
        fn(10, kwonly1=20)  # Ok.

    This behaviour will work with the `positional.method` and
    `positional.classmethod` helper functions as well::

        class MyClass(object):

            @positional.classmethod()
            def my_method(cls, pos1, kwonly1=None):
                ...

        MyClass.my_method(10)  # Ok.
        MyClass.my_method(10, 20)  # Raises exception.
        MyClass.my_method(10, kwonly1=20)  # Ok.

    For compatibility reasons you may wish to not always raise an exception so
    a WARN mode is available. Rather than raise an exception a warning message
    will be logged::

        @positional(1, enforcement=positional.WARN):
        def fn(pos1, kwonly=1):
           ...

    Available modes are:

    - positional.EXCEPT - the default, raise an exception.
    - positional.WARN - log a warning on mistake.
    """

    EXCEPT = 'except'
    WARN = 'warn'

    def __init__(self, max_positional_args=None, enforcement=EXCEPT):
        self._max_positional_args = max_positional_args
        self._enforcement = enforcement

    @classmethod
    def method(cls, max_positional_args=None, enforcement=EXCEPT):
        if max_positional_args is not None:
            max_positional_args += 1

        def f(func):
            return cls(max_positional_args, enforcement)(func)
        return f

    @classmethod
    def classmethod(cls, *args, **kwargs):
        def f(func):
            return classmethod(cls.method(*args, **kwargs)(func))
        return f

    def __call__(self, func):
        if self._max_positional_args is None:
            spec = inspect.getargspec(func)
            self._max_positional_args = len(spec.args) - len(spec.defaults)

        plural = '' if self._max_positional_args == 1 else 's'

        @functools.wraps(func)
        def inner(*args, **kwargs):
            if len(args) > self._max_positional_args:
                message = ('%(name)s takes at most %(max)d positional '
                           'argument%(plural)s (%(given)d given)' %
                           {'name': func.__name__,
                            'max': self._max_positional_args,
                            'given': len(args),
                            'plural': plural})

                if self._enforcement == self.EXCEPT:
                    raise TypeError(message)
                elif self._enforcement == self.WARN:
                    logger.warn(message)

            return func(*args, **kwargs)

        return inner


def normalize_time(timestamp):
    """Normalize time in arbitrary timezone to UTC naive object."""
    offset = timestamp.utcoffset()
    if offset is None:
        return timestamp
    return timestamp.replace(tzinfo=None) - offset


def parse_isotime(timestr):
    """Parse time from ISO 8601 format."""
    try:
        return iso8601.parse_date(timestr)
    except iso8601.ParseError as e:
        raise ValueError(six.text_type(e))
    except TypeError as e:
        raise ValueError(six.text_type(e))


def from_utcnow(**timedelta_kwargs):
    """Calculate the time in the future from utcnow.

    :param \*\*timedelta_kwargs:
        Passed directly to :class:`datetime.timedelta` to add to the current
        time in UTC.
    :returns:
        The time in the future based on ``timedelta_kwargs``.
    :rtype:
        datetime.datetime
    """
    now = datetime.datetime.utcnow()
    delta = datetime.timedelta(**timedelta_kwargs)
    return now + delta


def before_utcnow(**timedelta_kwargs):
    """Calculate the time in the past from utcnow.

    :param \*\*timedelta_kwargs:
        Passed directly to :class:`datetime.timedelta` to subtract from the
        current time in UTC.
    :returns:
        The time in the past based on ``timedelta_kwargs``.
    :rtype:
        datetime.datetime
    """
    now = datetime.datetime.utcnow()
    delta = datetime.timedelta(**timedelta_kwargs)
    return now - delta
