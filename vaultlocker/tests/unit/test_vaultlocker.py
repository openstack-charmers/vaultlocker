
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
        super().__init__(*args, **kwds)
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
