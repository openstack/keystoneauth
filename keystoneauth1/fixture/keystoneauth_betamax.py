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

"""A fixture to wrap the session constructor for use with Betamax."""

from functools import partial

import betamax
import fixtures
import mock
import requests

from keystoneauth1 import session


class BetamaxFixture(fixtures.Fixture):

    def __init__(self, cassette_name, cassette_library_dir=None,
                 serializer=None, record=False):
        self.cassette_library_dir = cassette_library_dir
        self.serializer = serializer
        self.record = record
        self.cassette_name = cassette_name
        if serializer:
            betamax.Betamax.register_serializer(serializer)

    def setUp(self):
        super(BetamaxFixture, self).setUp()
        self.mockpatch = mock.patch.object(
            session, '_construct_session',
            partial(_construct_session_with_betamax, self))
        self.mockpatch.start()
        # Unpatch during cleanup
        self.addCleanup(self.mockpatch.stop)


def _construct_session_with_betamax(fixture, session_obj=None):
    # NOTE(morganfainberg): This function should contain the logic of
    # keystoneauth1.session._construct_session as it replaces the
    # _construct_session function to apply betamax magic to the requests
    # session object.
    if not session_obj:
        session_obj = requests.Session()
        # Use TCPKeepAliveAdapter to fix bug 1323862
        for scheme in list(session_obj.adapters.keys()):
            session_obj.mount(scheme, session.TCPKeepAliveAdapter())
    fixture.recorder = betamax.Betamax(
        session_obj, cassette_library_dir=fixture.cassette_library_dir)

    record = 'none'
    serializer = None

    if fixture.record in ['once', 'all', 'new_episodes']:
        record = fixture.record

    if fixture.serializer:
        serializer = fixture.serializer.name

    fixture.recorder.use_cassette(fixture.cassette_name,
                                  serialize_with=serializer,
                                  record=record)

    fixture.recorder.start()
    fixture.addCleanup(fixture.recorder.stop)
    return session_obj
