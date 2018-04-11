# -*- coding: utf-8 -*-

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

"""
test_systemd
----------------------------------

Tests for `systemd` module.
"""

import mock

from vaultlocker import systemd
from vaultlocker.tests.unit import base


class TestSystemD(base.TestCase):

    @mock.patch.object(systemd, 'subprocess')
    def test_enable(self, _subprocess):
        systemd.enable('my-service.service')
        _subprocess.check_call.assert_called_once_with(
            ['systemctl', 'enable', 'my-service.service']
        )
