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
test_boot_unlock
----------------------------------

Tests for `boot_unlock` module.
"""

from unittest import mock

from vaultlocker import boot_unlock
from vaultlocker.tests.unit import base


class TestBootUnlock(base.TestCase):

    @mock.patch.object(boot_unlock, 'pebble_layers')
    @mock.patch.object(boot_unlock, 'systemd')
    def test_register_uses_pebble_inside_snap(
            self, _systemd, _pebble_layers):
        with mock.patch.dict(
                boot_unlock.os.environ, {'SNAP': '/snap/vaultlocker'}):
            boot_unlock.register('test-uuid', '/path/to/conf', timeout=42)

        _pebble_layers.register_boot_unlock.assert_called_once_with(
            'test-uuid', '/path/to/conf', 42,
        )
        _systemd.register_decrypt_service.assert_not_called()

    @mock.patch.object(boot_unlock, 'pebble_layers')
    @mock.patch.object(boot_unlock, 'systemd')
    def test_register_uses_systemd_outside_snap(
            self, _systemd, _pebble_layers):
        with mock.patch.dict(boot_unlock.os.environ, {}, clear=True):
            boot_unlock.register('test-uuid', '/path/to/conf')

        _systemd.register_decrypt_service.assert_called_once_with(
            'test-uuid', '/path/to/conf',
        )
        _pebble_layers.register_boot_unlock.assert_not_called()

    def test_running_in_snap_detects_environment(self):
        with mock.patch.dict(
                boot_unlock.os.environ, {'SNAP': '/snap/vaultlocker'}):
            self.assertTrue(boot_unlock.running_in_snap())

        with mock.patch.dict(boot_unlock.os.environ, {}, clear=True):
            self.assertFalse(boot_unlock.running_in_snap())
