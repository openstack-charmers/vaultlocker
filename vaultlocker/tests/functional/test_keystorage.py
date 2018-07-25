# -*- coding: utf-8 -*-

# Copyright 2010-2011 OpenStack Foundation
# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
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

import mock

from vaultlocker import shell
from vaultlocker.tests.functional import base


@mock.patch.object(shell.dmcrypt, 'udevadm_settle')
@mock.patch.object(shell.dmcrypt, 'udevadm_rescan')
@mock.patch.object(shell, 'systemd')
@mock.patch.object(shell.dmcrypt, 'luks_format')
@mock.patch.object(shell.dmcrypt, 'luks_open')
class KeyStorageTestCase(base.VaultlockerFuncBaseTestCase):

    """Test storage and retrieval of dm-crypt keys from vault"""

    def test_encrypt(self, _luks_open, _luks_format, _systemd,
                     _udevadm_rescan, _udevadm_settle):
        """Test encrypt function stores correct data in vault"""
        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']
        args.retry = -1

        shell.encrypt(args, self.config)
        _luks_format.assert_called_once_with(mock.ANY,
                                             '/dev/sdb',
                                             'passed-UUID')
        _luks_open.assert_called_once_with(mock.ANY,
                                           'passed-UUID')
        _systemd.enable.assert_called_once_with(
            'vaultlocker-decrypt@passed-UUID.service'
        )
        _udevadm_rescan.assert_called_once_with('/dev/sdb')
        _udevadm_settle.assert_called_once_with('passed-UUID')

        stored_data = self.vault_client.read(
            shell._get_vault_path('passed-UUID',
                                  self.config)
        )
        self.assertIsNotNone(stored_data,
                             'Key data missing from vault')
        self.assertTrue('dmcrypt_key' in stored_data['data'],
                        'dm-crypt key data is missing')

    def test_decrypt(self, _luks_open, _luks_format, _systemd,
                     _udevadm_rescan, _udevadm_settle):
        """Test decrypt function retrieves correct key from vault"""
        args = mock.MagicMock()
        args.uuid = ['passed-UUID']
        args.retry = -1

        self.vault_client.write(shell._get_vault_path('passed-UUID',
                                                      self.config),
                                dmcrypt_key='testkey')

        shell.decrypt(args, self.config)
        _luks_format.assert_not_called()
        _systemd.enable.assert_not_called()
        _luks_open.assert_called_once_with('testkey',
                                           'passed-UUID')

    def test_decrypt_missing_key(self, _luks_open, _luks_format, _systemd,
                                 _udevadm_rescan, _udevadm_settle):
        """Test decrypt function errors if a key is missing from vault"""
        args = mock.MagicMock()
        args.uuid = ['passed-UUID']
        args.retry = -1

        self.assertRaises(ValueError,
                          shell.decrypt,
                          args, self.config)
        _luks_format.assert_not_called()
        _systemd.enable.assert_not_called()
        _luks_open.assert_not_called()
