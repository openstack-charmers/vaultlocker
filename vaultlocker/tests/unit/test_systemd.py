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

from unittest import mock

from vaultlocker import systemd
from vaultlocker.tests.unit import base


class TestSystemD(base.TestCase):

    @mock.patch.object(systemd, 'subprocess')
    def test_enable(self, _subprocess):
        systemd.enable('my-service.service')
        _subprocess.check_call.assert_called_once_with(
            ['systemctl', 'enable', 'my-service.service']
        )

    def test_config_dropin_path(self):
        self.assertEqual(
            '/etc/systemd/system/'
            'vaultlocker-decrypt@test-uuid.service.d/config.conf',
            systemd.config_dropin_path(
                'vaultlocker-decrypt@test-uuid.service',
            ),
        )

    @mock.patch.object(systemd.os, 'makedirs')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_write_config_dropin(self, _open, _makedirs):
        systemd.write_config_dropin(
            'vaultlocker-decrypt@test-uuid.service',
            '/var/snap/vaultlocker/common/app/vaultlocker.conf',
        )

        _makedirs.assert_called_once_with(
            '/etc/systemd/system/'
            'vaultlocker-decrypt@test-uuid.service.d',
            exist_ok=True,
        )
        _open.assert_called_once_with(
            '/etc/systemd/system/'
            'vaultlocker-decrypt@test-uuid.service.d/config.conf',
            'w',
        )
        handle = _open()
        handle.write.assert_called_once_with(
            '[Service]\n'
            'Environment=VAULTLOCKER_CONFIG='
            '/var/snap/vaultlocker/common/app/vaultlocker.conf\n'
        )

    @mock.patch.object(systemd, 'enable')
    @mock.patch.object(systemd, 'write_config_dropin')
    def test_register_decrypt_service(self, _write_dropin, _enable):
        systemd.register_decrypt_service('test-uuid', '/path/to/conf')

        _write_dropin.assert_called_once_with(
            'vaultlocker-decrypt@test-uuid.service',
            '/path/to/conf',
        )
        _enable.assert_called_once_with(
            'vaultlocker-decrypt@test-uuid.service',
        )
