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

import configparser
import subprocess

from unittest import mock

import hvac

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

        def side_effect(_, key, **kwargs):
            return self._test_config.get(
                key,
                kwargs.get('fallback'),
            )
        self.config.get.side_effect = side_effect

    def _hostname_config(self, hostname=None):
        config = configparser.ConfigParser()
        config.add_section('vault')

        if hostname is not None:
            config.set('DEFAULT', 'hostname', hostname)

        return config

    @mock.patch.object(shell.hvac, 'Client')
    def test_vault_client_uses_approle_login(self, _client):
        client = _client.return_value

        result = shell._vault_client(self.config)

        client.auth.approle.login.assert_called_once_with(
            role_id=self._test_config['approle'],
            secret_id=self._test_config['secret_id'],
        )
        client.auth_approle.assert_not_called()
        self.assertIs(result, client)

    @mock.patch.object(shell.vault, 'KVStore')
    def test_vault_store_uses_configured_mount_and_version(self, _kv_store):
        client = mock.MagicMock()

        result = shell._vault_store(client, self.config)

        _kv_store.get_store.assert_called_once_with(
            client=client,
            mount_point='vaultlocker-test',
            kv_version='1',
        )
        self.assertIs(result, _kv_store.get_store.return_value)

    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    def test_encrypt(self, _dmcrypt, _systemd, _vault_store, _get_hostname):
        _get_hostname.return_value = 'host'
        _dmcrypt.generate_key.return_value = 'testkey'

        store = _vault_store.return_value
        store.read.return_value = {
            'dmcrypt_key': 'testkey',
        }

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()

        shell._encrypt_block_device(args, client, self.config)

        store.write.assert_called_once_with(
            'host/passed-UUID',
            {'dmcrypt_key': 'testkey'},
        )
        store.read.assert_called_once_with('host/passed-UUID')

        _dmcrypt.luks_format.assert_called_once_with(
            'testkey', '/dev/sdb', 'passed-UUID'
        )
        _dmcrypt.luks_open.assert_called_once_with(
            'testkey', 'passed-UUID'
        )
        _systemd.enable.assert_called_once_with(
            'vaultlocker-decrypt@passed-UUID.service'
        )

    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    def test_encrypt_key_mismatch(self, _dmcrypt, _systemd,
                                  _vault_store, _get_hostname):
        _get_hostname.return_value = 'host'
        _dmcrypt.generate_key.return_value = 'testkey'

        store = _vault_store.return_value
        store.read.return_value = {
            'dmcrypt_key': 'brokendata',
        }

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()

        self.assertRaises(
            exceptions.VaultKeyMismatch,
            shell._encrypt_block_device,
            args, client, self.config
        )

        _dmcrypt.luks_format.assert_not_called()
        _systemd.enable.assert_not_called()

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'dmcrypt')
    def test_decrypt(self, _dmcrypt, _vault_store, _get_hostname,
                     _device_exists):
        _get_hostname.return_value = 'host'

        store = _vault_store.return_value
        store.read.return_value = {
            'dmcrypt_key': 'testkey',
        }

        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        client = mock.MagicMock()

        shell._decrypt_block_device(args, client, self.config)

        store.read.assert_called_once_with('host/passed-UUID')
        _dmcrypt.luks_open.assert_called_once_with(
            'testkey', 'passed-UUID'
        )

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'dmcrypt')
    def test_decrypt_missing_key(self, _dmcrypt, _vault_store, _get_hostname,
                                 _device_exists):
        _get_hostname.return_value = 'host'

        store = _vault_store.return_value
        store.read.side_effect = hvac.exceptions.InvalidPath('missing')

        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        client = mock.MagicMock()

        with self.assertRaises(ValueError) as error:
            shell._decrypt_block_device(args, client, self.config)

        self.assertEqual(
            'Unable to locate key for passed-UUID',
            str(error.exception),
        )
        _dmcrypt.luks_open.assert_not_called()

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    def test_decrypt_vault_error(self, _vault_store, _get_hostname,
                                 _device_exists):
        _get_hostname.return_value = 'host'

        store = _vault_store.return_value
        store.read.side_effect = hvac.exceptions.Forbidden('denied')

        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        client = mock.MagicMock()

        self.assertRaises(
            hvac.exceptions.Forbidden,
            shell._decrypt_block_device,
            args, client, self.config
        )

    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, '_device_exists', return_value=True)
    def test_decrypt_already_exists(self, _device_exists, _vault_store):
        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        client = mock.MagicMock()

        self.assertIsNone(
            shell._decrypt_block_device(args, client, self.config)
        )

        _vault_store.assert_not_called()

    @mock.patch.object(shell, 'get_hostname')
    def test_get_vault_path(self, _get_hostname):
        _get_hostname.return_value = 'myhost'

        self.assertEqual(
            shell._get_vault_path('my-UUID', self.config),
            'vaultlocker-test/myhost/my-UUID'
        )

    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    def test_encrypt_luks_failure(self, _dmcrypt, _systemd,
                                  _vault_store, _get_hostname):
        _get_hostname.return_value = 'host'
        _dmcrypt.generate_key.return_value = 'testkey'
        _dmcrypt.luks_format.side_effect = \
            subprocess.CalledProcessError(returncode=-1,
                                          cmd='echo Unit Test')

        store = _vault_store.return_value
        store.read.return_value = {
            'dmcrypt_key': 'testkey',
        }

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()

        self.assertRaises(
            exceptions.LUKSFailure,
            shell._encrypt_block_device,
            args, client, self.config
        )

        store.delete.assert_called_once_with('host/passed-UUID')
        _systemd.enable.assert_not_called()

    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'dmcrypt')
    def test_vault_write_operation(self, _dmcrypt, _vault_store,
                                   _get_hostname):
        _get_hostname.return_value = 'host'
        _dmcrypt.generate_key.return_value = 'testkey'

        store = _vault_store.return_value
        store.write.side_effect = hvac.exceptions.Forbidden('denied')

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()

        self.assertRaises(
            exceptions.VaultWriteError,
            shell._encrypt_block_device,
            args, client, self.config
        )

    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'dmcrypt')
    def test_vault_read_operation(self, _dmcrypt, _vault_store,
                                  _get_hostname):
        _get_hostname.return_value = 'host'
        _dmcrypt.generate_key.return_value = 'testkey'

        store = _vault_store.return_value
        store.read.side_effect = hvac.exceptions.Forbidden('denied')

        args = mock.MagicMock()
        args.uuid = 'passed-UUID'
        args.block_device = ['/dev/sdb']

        client = mock.MagicMock()

        self.assertRaises(
            exceptions.VaultReadError,
            shell._encrypt_block_device,
            args, client, self.config
        )

    @mock.patch.object(shell, 'socket')
    @mock.patch.object(shell, 'platform')
    def test_get_hostname_uses_configured_value(self, _platform, _socket):
        self.assertEqual(
            'configured-host',
            shell.get_hostname(
                self._hostname_config('configured-host')
            ),
        )

        _platform.node.assert_not_called()
        _socket.gethostname.assert_not_called()

    @mock.patch.object(shell, 'socket')
    @mock.patch.object(shell, 'platform')
    def test_get_hostname_uses_platform_node(self, _platform, _socket):
        _platform.node.return_value = 'node-host'

        self.assertEqual(
            'node-host',
            shell.get_hostname(self._hostname_config()),
        )

        _socket.gethostname.assert_not_called()

    @mock.patch.object(shell, 'socket')
    @mock.patch.object(shell, 'platform')
    def test_get_hostname_uses_socket_fallback(self, _platform, _socket):
        _platform.node.return_value = ''
        _socket.gethostname.return_value = 'socket-host'

        self.assertEqual(
            'socket-host',
            shell.get_hostname(self._hostname_config()),
        )

        _socket.gethostname.assert_called_once_with()

    @mock.patch.object(shell, 'socket')
    @mock.patch.object(shell, 'platform')
    def test_get_hostname_raises_when_socket_fails(self, _platform, _socket):
        _platform.node.return_value = ''
        _socket.gethostname.side_effect = OSError('no hostname')

        with self.assertRaises(RuntimeError) as error:
            shell.get_hostname(self._hostname_config())

        self.assertIn(
            'Unable to determine hostname',
            str(error.exception),
        )

    @mock.patch.object(shell, 'sys')
    def test_read_existing_key_from_piped_stdin(self, _sys):
        _sys.stdin.isatty.return_value = False
        _sys.stdin.buffer.read.return_value = b'existing-key'

        self.assertEqual(
            b'existing-key',
            shell._read_existing_key(None),
        )

        _sys.stdin.buffer.read.assert_called_once_with()

    @mock.patch.object(shell.getpass, 'getpass')
    @mock.patch.object(shell, 'sys')
    def test_read_existing_key_prompts_for_terminal_stdin(
            self, _sys, _getpass):
        _sys.stdin.isatty.return_value = True
        _getpass.return_value = 'some'

        self.assertEqual(
            b'some',
            shell._read_existing_key(None),
        )

        _getpass.assert_called_once_with(
            'Existing LUKS passphrase: ',
        )

    @mock.patch('builtins.open', new_callable=mock.mock_open,
                read_data=b'existing-key')
    def test_read_existing_key_from_file(self, _open):
        self.assertEqual(
            b'existing-key',
            shell._read_existing_key('/path/to/key'),
        )

        _open.assert_called_once_with('/path/to/key', 'rb')

    @mock.patch.object(shell.dmcrypt, 'generate_key')
    def test_get_or_create_managed_key_reuses_existing(
            self, _generate_key):
        store = mock.MagicMock()
        store.read.return_value = {
            'dmcrypt_key': 'managed-key',
        }

        self.assertEqual(
            'managed-key',
            shell._get_or_create_managed_key(
                store,
                'host/test-uuid',
            ),
        )

        store.read.assert_called_once_with('host/test-uuid')
        _generate_key.assert_not_called()

    @mock.patch.object(shell, '_store_and_validate_key')
    @mock.patch.object(shell.dmcrypt, 'generate_key')
    def test_get_or_create_managed_key_creates_missing(
            self, _generate_key, _store_and_validate_key):
        store = mock.MagicMock()
        store.read.side_effect = hvac.exceptions.InvalidPath(
            'missing',
        )
        _generate_key.return_value = 'managed-key'

        self.assertEqual(
            'managed-key',
            shell._get_or_create_managed_key(
                store,
                'host/test-uuid',
            ),
        )

        _generate_key.assert_called_once_with()
        _store_and_validate_key.assert_called_once_with(
            store,
            'host/test-uuid',
            'managed-key',
        )

    @mock.patch.object(shell.dmcrypt, 'generate_key')
    def test_get_or_create_managed_key_error(
            self, _generate_key):
        store = mock.MagicMock()
        store.read.side_effect = hvac.exceptions.Forbidden(
            'denied',
        )

        with self.assertRaises(hvac.exceptions.Forbidden):
            shell._get_or_create_managed_key(
                store,
                'host/test-uuid',
            )

        _generate_key.assert_not_called()

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, '_get_or_create_managed_key')
    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    def test_enroll_block_device(
            self, _dmcrypt, _systemd, _vault_store,
            _get_hostname, _get_managed_key, _device_exists):
        _get_hostname.return_value = 'host'
        _get_managed_key.return_value = 'managed-key'

        _dmcrypt.luks_uuid.return_value = 'test-uuid'
        _dmcrypt.luks_test_key.side_effect = [
            True,
            False,
            True,
        ]

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        client = mock.MagicMock()

        shell._enroll_block_device(
            args,
            client,
            self.config,
            b'existing-key',
        )

        _dmcrypt.luks_uuid.assert_called_once_with('/dev/sdb')
        _dmcrypt.luks_test_key.assert_has_calls([
            mock.call(b'existing-key', '/dev/sdb'),
            mock.call('managed-key', '/dev/sdb'),
            mock.call('managed-key', '/dev/sdb'),
        ])
        _get_managed_key.assert_called_once_with(
            _vault_store.return_value,
            'host/test-uuid',
        )
        _dmcrypt.luks_add_key.assert_called_once_with(
            b'existing-key',
            'managed-key',
            '/dev/sdb',
        )
        _dmcrypt.luks_open.assert_called_once_with(
            'managed-key',
            'test-uuid',
        )
        _systemd.enable.assert_called_once_with(
            'vaultlocker-decrypt@test-uuid.service',
        )

    @mock.patch.object(shell, '_device_exists', return_value=True)
    @mock.patch.object(shell, '_get_or_create_managed_key')
    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    def test_enroll_block_device_already_enrolled(
            self, _dmcrypt, _systemd, _vault_store,
            _get_hostname, _get_managed_key, _device_exists):
        _get_hostname.return_value = 'host'
        _get_managed_key.return_value = 'managed-key'

        _dmcrypt.luks_uuid.return_value = 'test-uuid'
        _dmcrypt.luks_test_key.side_effect = [
            True,
            True,
        ]

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        shell._enroll_block_device(
            args,
            mock.MagicMock(),
            self.config,
            b'existing-key',
        )

        _dmcrypt.luks_add_key.assert_not_called()
        _dmcrypt.luks_open.assert_not_called()
        _systemd.enable.assert_called_once_with(
            'vaultlocker-decrypt@test-uuid.service',
        )

    @mock.patch.object(shell, '_get_or_create_managed_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'systemd')
    @mock.patch.object(shell, 'dmcrypt')
    def test_enroll_block_device_rejects_invalid_existing_key(
            self, _dmcrypt, _systemd, _vault_store,
            _get_managed_key):
        _dmcrypt.luks_uuid.return_value = 'test-uuid'
        _dmcrypt.luks_test_key.return_value = False

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        with self.assertRaises(ValueError) as error:
            shell._enroll_block_device(
                args,
                mock.MagicMock(),
                self.config,
                b'wrong-key',
            )

        self.assertEqual(
            'Existing key does not unlock /dev/sdb',
            str(error.exception),
        )
        _vault_store.assert_not_called()
        _get_managed_key.assert_not_called()
        _dmcrypt.luks_add_key.assert_not_called()
        _dmcrypt.luks_open.assert_not_called()
        _systemd.enable.assert_not_called()

    @mock.patch.object(
        shell.sys,
        'argv',
        [
            'vaultlocker',
            'enroll',
            '/dev/sdb',
        ],
    )
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'enroll')
    def test_main_parses_enroll(
            self, _enroll, _get_config):
        _get_config.return_value = self.config

        shell.main()

        _get_config.assert_called_once_with(
            shell.DEFAULT_CONF_FILE,
        )
        _enroll.assert_called_once()

        args, config = _enroll.call_args[0]
        self.assertIsNone(args.existing_key_file)
        self.assertEqual(['/dev/sdb'], args.block_device)
        self.assertIs(self.config, config)


class TestKVConfiguration(base.TestCase):

    def _config(self, kv_version=None):
        config = configparser.ConfigParser()
        config.add_section('vault')
        config.set('vault', 'backend', 'vaultlocker-test')

        if kv_version is not None:
            config.set('vault', 'kv_version', kv_version)

        return config

    def test_kv_version_defaults_to_one(self):
        self.assertEqual(
            '1',
            shell._get_kv_version(self._config()),
        )

    def test_kv_version_one(self):
        self.assertEqual(
            '1',
            shell._get_kv_version(self._config('1')),
        )

    def test_kv_version_two(self):
        self.assertEqual(
            '2',
            shell._get_kv_version(self._config('2')),
        )

    def test_kv_version_rejects_other_number(self):
        with self.assertRaises(ValueError) as error:
            shell._get_kv_version(self._config('3'))

        self.assertIn(
            "must be '1' or '2'",
            str(error.exception),
        )

    @mock.patch.object(shell, 'get_hostname')
    def test_secret_path_is_relative_to_mount(self, _get_hostname):
        _get_hostname.return_value = 'test-host'

        self.assertEqual(
            'test-host/test-uuid',
            shell._vault_secret_path('test-uuid', self._config()),
        )
