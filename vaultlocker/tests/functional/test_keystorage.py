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

from unittest import mock

from vaultlocker import shell
from vaultlocker.tests.functional import base


@mock.patch.object(shell.dmcrypt, 'udevadm_settle')
@mock.patch.object(shell.dmcrypt, 'udevadm_rescan')
@mock.patch.object(shell, 'boot_unlock')
@mock.patch.object(shell.dmcrypt, 'luks_format')
@mock.patch.object(shell.dmcrypt, 'luks_open')
class KeyStorageTestCase(base.VaultlockerFuncBaseTestCase):

    """Functional tests for vaultlocker key storage.

    The device operations are mocked; the Vault interactions are real.
    Subclasses run this suite against KV version 1 and 2.
    """

    def test_encrypt(self, _luks_open, _luks_format, _boot_unlock,
                     _udevadm_rescan, _udevadm_settle):
        """Test encrypt function stores correct data in vault"""
        _boot_unlock.running_in_snap.return_value = False
        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']
        args.retry = -1
        args.config = self.config_path

        # The device itself is not real in this test environment: tell
        # the device-state check it is looking at a device with no
        # LUKS header yet, the normal case for a first-time encrypt.
        with mock.patch.object(
                shell.dmcrypt, 'luks_uuid',
                side_effect=shell.subprocess.CalledProcessError(
                    returncode=1, cmd='cryptsetup luksUUID',
                )):
            shell.encrypt(args, self.config)

        _luks_format.assert_called_once_with(mock.ANY, '/dev/sdb',
                                             'passed-UUID')
        _luks_open.assert_called_once_with(mock.ANY, 'passed-UUID',
                                           '/dev/sdb')
        _boot_unlock.register.assert_called_once_with('passed-UUID',
                                                      self.config_path)
        _udevadm_rescan.assert_called_once_with('/dev/sdb')
        _udevadm_settle.assert_called_once_with('passed-UUID')

        stored = self.vault_store().read(self.secret_path('passed-UUID'))
        self.assertIn('dmcrypt_key', stored,
                      'dm-crypt key data is missing from Vault')

    def test_encrypt_does_not_replace_a_different_key(
            self, _luks_open, _luks_format, _boot_unlock,
            _udevadm_rescan, _udevadm_settle):
        """A UUID collision leaves the existing Vault secret untouched."""
        path = self.secret_path('passed-UUID')
        self.vault_store().write(
            path, {'dmcrypt_key': 'existing-managed-key'},
        )

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']
        args.retry = -1
        args.config = self.config_path

        with mock.patch.object(
                shell.dmcrypt, 'luks_uuid',
                side_effect=shell.subprocess.CalledProcessError(
                    returncode=1, cmd='cryptsetup luksUUID',
                )):
            self.assertRaises(
                shell.exceptions.VaultKeyMismatch,
                shell.encrypt, args, self.config,
            )

        self.assertEqual(
            {'dmcrypt_key': 'existing-managed-key'},
            self.vault_store().read(path),
        )
        _luks_format.assert_not_called()

    def test_encrypt_does_not_replace_malformed_data(
            self, _luks_open, _luks_format, _boot_unlock,
            _udevadm_rescan, _udevadm_settle):
        """Malformed data at a proposed UUID is preserved for inspection."""
        path = self.secret_path('passed-UUID')
        malformed = {'unexpected': 'value'}
        self.vault_store().write(path, malformed)

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']
        args.retry = -1
        args.config = self.config_path

        with mock.patch.object(
                shell.dmcrypt, 'luks_uuid',
                side_effect=shell.subprocess.CalledProcessError(
                    returncode=1, cmd='cryptsetup luksUUID',
                )):
            self.assertRaises(
                shell.exceptions.ManagedKeyInvalidError,
                shell.encrypt, args, self.config,
            )

        self.assertEqual(malformed, self.vault_store().read(path))
        _luks_format.assert_not_called()

    def test_decrypt(self, _luks_open, _luks_format, _boot_unlock,
                     _udevadm_rescan, _udevadm_settle):
        """Decrypt reads the key from Vault and opens the mapper."""
        args = mock.MagicMock()
        args.uuid = ['passed-UUID']
        args.retry = -1
        args.config = self.config_path

        self.vault_store().write(
            self.secret_path('passed-UUID'),
            {'dmcrypt_key': 'testkey'},
        )

        with mock.patch.object(shell, '_device_exists', return_value=False):
            shell.decrypt(args, self.config)

        _luks_format.assert_not_called()
        _boot_unlock.register.assert_not_called()
        _luks_open.assert_called_once_with('testkey', 'passed-UUID')

    def test_decrypt_missing_key(self, _luks_open, _luks_format, _boot_unlock,
                                 _udevadm_rescan, _udevadm_settle):
        """Decrypt errors if the key is missing from Vault."""
        args = mock.MagicMock()
        args.uuid = ['passed-UUID']
        args.retry = -1
        args.config = self.config_path

        with mock.patch.object(shell, '_device_exists', return_value=False):
            self.assertRaises(
                shell.exceptions.ManagedKeyNotFoundError,
                shell.decrypt, args, self.config,
            )

        _luks_format.assert_not_called()
        _boot_unlock.register.assert_not_called()
        _luks_open.assert_not_called()

    def test_enroll_adds_managed_key(self, _luks_open, _luks_format,
                                     _boot_unlock, _udevadm_rescan,
                                     _udevadm_settle):
        """Enroll adds a Vault-managed key to an existing LUKS device."""
        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        args.retry = -1
        args.config = self.config_path

        with mock.patch.object(shell.dmcrypt, 'luks_uuid',
                               return_value='passed-UUID'), \
                mock.patch.object(shell.dmcrypt, 'luks_test_key',
                                  side_effect=[True, True]), \
                mock.patch.object(shell.dmcrypt, 'luks_add_key') as add_key, \
                mock.patch.object(shell, '_device_exists',
                                  return_value=False):
            shell._enroll_block_device(args, self.vault_client,
                                       self.config, lambda: b'operatorpass')

        add_key.assert_called_once_with(b'operatorpass', mock.ANY,
                                        '/dev/sdb')
        _luks_open.assert_called_once_with(mock.ANY, 'passed-UUID',
                                           '/dev/sdb')
        _boot_unlock.register.assert_called_once_with('passed-UUID',
                                                      self.config_path)

        stored = self.vault_store().read(self.secret_path('passed-UUID'))
        self.assertIn('dmcrypt_key', stored,
                      'managed key data is missing from Vault')

    def test_enroll_reuses_existing_managed_key(self, _luks_open,
                                                _luks_format, _boot_unlock,
                                                _udevadm_rescan,
                                                _udevadm_settle):
        """A managed key already in Vault is reused without re-adding it."""
        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        args.retry = -1
        args.config = self.config_path

        self.vault_store().write(
            self.secret_path('passed-UUID'),
            {'dmcrypt_key': 'existing-managed-key'},
        )

        # The managed key already unlocks the device, so the original
        # credential must never be requested.
        never_load_credential = mock.MagicMock(
            side_effect=AssertionError('credential should not be read'),
        )

        with mock.patch.object(shell.dmcrypt, 'luks_uuid',
                               return_value='passed-UUID'), \
                mock.patch.object(shell.dmcrypt, 'luks_test_key',
                                  return_value=True), \
                mock.patch.object(shell.dmcrypt, 'luks_add_key') as add_key, \
                mock.patch.object(shell, '_device_exists',
                                  return_value=True):
            shell._enroll_block_device(args, self.vault_client,
                                       self.config, never_load_credential)

        never_load_credential.assert_not_called()
        add_key.assert_not_called()
        _luks_open.assert_not_called()
        _boot_unlock.register.assert_called_once_with('passed-UUID',
                                                      self.config_path)


class KeyStorageV1TestCase(KeyStorageTestCase):
    """Run the key storage suite against KV version 1."""

    kv_version = '1'


class KeyStorageV2TestCase(KeyStorageTestCase):
    """Run the key storage suite against KV version 2."""

    kv_version = '2'
