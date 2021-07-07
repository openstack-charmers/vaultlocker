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
test_vaultlocker
----------------------------------

Tests for `vaultlocker` module.
"""

import subprocess

from unittest import mock

from vaultlocker import exceptions
from vaultlocker import shell
from vaultlocker.tests.unit import base


class TestVaultlocker(base.TestCase):

    _test_config = {
        'url': 'https://vaultlocker.test.com',
        'approle': '85e4c349-7547-4ad5-9172-d82a45d87b3e',
        'secret_id': '9428ad25-7b4a-442f-8f20-f23be0575146',
        'backend': 'vaultlocker-test',
    }

    def __init__(self, *args, **kwds):
        super(TestVaultlocker, self).__init__(*args, **kwds)
        self.config = mock.MagicMock()

        def side_effect(_, k, **kwargs):
            return self._test_config.get(k)
        self.config.get.side_effect = side_effect

    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    @mock.patch.object(shell, '_get_vault_path')
    def test_encrypt(self, _get_vault_path, _dmcrypt, _systemd):
        _get_vault_path.return_value = 'backend/host/uuid'
        _dmcrypt.generate_key.return_value = 'testkey'

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()
        client.read.return_value = {
            'data': {
                'dmcrypt_key': 'testkey'
            }
        }

        shell._encrypt_block_device(args, client, self.config)

        _dmcrypt.luks_format.assert_called_with(
            'testkey', '/dev/sdb', 'passed-UUID'
        )
        _dmcrypt.luks_open.assert_called_with(
            'testkey', 'passed-UUID'
        )
        _systemd.enable.assert_called_with(
            'vaultlocker-decrypt@passed-UUID.service'
        )

    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    @mock.patch.object(shell, '_get_vault_path')
    def test_encrypt_vault_failure(self, _get_vault_path,
                                   _dmcrypt, _systemd):
        _get_vault_path.return_value = 'backend/host/uuid'
        _dmcrypt.generate_key.return_value = 'testkey'

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()
        client.read.return_value = {
            'data': {
                'dmcrypt_key': 'brokendata'
            }
        }

        self.assertRaises(
            exceptions.VaultKeyMismatch,
            shell._encrypt_block_device,
            args, client, self.config
        )

    @mock.patch.object(shell, 'os')
    @mock.patch.object(shell, 'dmcrypt')
    @mock.patch.object(shell, '_get_vault_path')
    def test_decrypt(self, _get_vault_path, _dmcrypt, _os):
        _get_vault_path.return_value = 'backend/host/uuid'
        _os.path.exists.return_value = False
        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        client = mock.MagicMock()
        client.read.return_value = {
            'data': {
                'dmcrypt_key': 'testkey'
            }
        }

        shell._decrypt_block_device(args, client, self.config)

        _dmcrypt.luks_open.assert_called_with(
            'testkey', 'passed-UUID'
        )

    @mock.patch.object(shell, 'os')
    @mock.patch.object(shell, '_get_vault_path')
    def test_decrypt_already_exists(self, _get_vault_path, _os):
        _os.path.exists.return_value = True

        args = mock.MagicMock()
        args.uuid = ['passed-UUID']
        client = mock.MagicMock()
        client.read.return_value = {
            'data': {
                'dmcrypt_key': 'testkey'
            }
        }

        self.assertIsNone(
            shell._decrypt_block_device(args, client, self.config))

        _get_vault_path.assert_not_called()

    @mock.patch.object(shell, 'socket')
    def test_get_vault_path(self, _socket):
        _socket.gethostname.return_value = 'myhost'
        self.assertEqual(shell._get_vault_path('my-UUID', self.config),
                         'vaultlocker-test/myhost/my-UUID')

    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    @mock.patch.object(shell, '_get_vault_path')
    def test_encrypt_luks_failure(self, _get_vault_path, _dmcrypt, _systemd):
        _get_vault_path.return_value = 'backend/host/uuid'
        _dmcrypt.generate_key.return_value = 'testkey'
        _dmcrypt.luks_format.side_effect = \
            subprocess.CalledProcessError(returncode=-1,
                                          cmd="echo Unit Test")

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()
        client.read.return_value = {
            'data': {
                'dmcrypt_key': 'testkey'
            }
        }

        self.assertRaises(
            exceptions.LUKSFailure,
            shell._encrypt_block_device,
            args, client, self.config
        )

        client.delete.assert_called_once_with('backend/host/uuid')

    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    @mock.patch.object(shell, '_get_vault_path')
    def test_vault_write_operation(self, _get_vault_path,
                                   _dmcrypt, _systemd):
        _get_vault_path.return_value = 'backend/host/uuid'
        _dmcrypt.generate_key.return_value = 'testkey'

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()
        client.read.return_value = {
            'data': {
                'dmcrypt_key': 'testkey'
            }
        }

        self.assertIsNot(
            exceptions.VaultWriteError,
            shell._encrypt_block_device(
                args,
                client,
                self.config))

        client.write.side_effect = exceptions.VaultWriteError(
            'backend/host/uuid', 'Write Failed')
        self.assertRaises(
            exceptions.VaultWriteError,
            shell._encrypt_block_device,
            args,
            client,
            self.config)

    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    @mock.patch.object(shell, '_get_vault_path')
    def test_vault_read_operation(self, _get_vault_path,
                                  _dmcrypt, _systemd):
        _get_vault_path.return_value = 'backend/host/uuid'
        _dmcrypt.generate_key.return_value = 'testkey'

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()
        client.read.return_value = {
            'data': {
                'dmcrypt_key': 'testkey'
            }
        }

        self.assertIsNot(
            exceptions.VaultReadError,
            shell._encrypt_block_device(
                args,
                client,
                self.config))

        client.read.side_effect = exceptions.VaultReadError(
            'backend/host/uuid', 'Write Failed')
        self.assertRaises(
            exceptions.VaultReadError,
            shell._encrypt_block_device,
            args,
            client,
            self.config)
