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
import io
import json
import subprocess

from unittest import mock

import hvac

from vaultlocker import exceptions
from vaultlocker.exit_codes import ExitCode
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

    def test_get_config_rejects_path_with_whitespace(self):
        invalid_paths = [
            '/path with spaces/vaultlocker.conf',
            '/path\twith-tab/vaultlocker.conf',
        ]

        for config_path in invalid_paths:
            with self.subTest(config_path=config_path):
                with self.assertRaises(ValueError):
                    shell.get_config(config_path)

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

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'boot_unlock')
    @mock.patch.object(shell, 'dmcrypt')
    def test_decrypt(self, _dmcrypt, _boot_unlock, _vault_store,
                     _get_hostname, _device_exists):
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
        _boot_unlock.register.assert_not_called()

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'get_hostname')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'dmcrypt')
    def test_decrypt_missing_key(self, _dmcrypt, _vault_store, _get_hostname,
                                 _device_exists):
        _get_hostname.return_value = 'host'

        store = _vault_store.return_value
        store.mount_point = 'vaultlocker-test'
        store.read.side_effect = hvac.exceptions.InvalidPath('missing')

        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        client = mock.MagicMock()

        with self.assertRaises(exceptions.ManagedKeyNotFoundError) as error:
            shell._decrypt_block_device(args, client, self.config)

        self.assertIn(
            'vaultlocker-test/host/passed-UUID',
            str(error.exception),
        )
        _dmcrypt.luks_open.assert_not_called()

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'get_hostname', return_value='host')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'dmcrypt')
    def test_decrypt_rejects_invalid_managed_key_data(
            self, _dmcrypt, _vault_store, _get_hostname, _device_exists):
        store = _vault_store.return_value
        store.mount_point = 'vaultlocker-test'

        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        invalid_data = (
            'not-a-mapping',
            {},
            {'dmcrypt_key': ''},
        )
        for stored_data in invalid_data:
            with self.subTest(stored_data=stored_data):
                store.read.return_value = stored_data
                with self.assertRaises(exceptions.ManagedKeyInvalidError):
                    shell._decrypt_block_device(
                        args, mock.MagicMock(), self.config,
                    )

        _dmcrypt.luks_open.assert_not_called()

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'get_hostname', return_value='host')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell, 'dmcrypt')
    def test_decrypt_wraps_mapper_open_failures(
            self, _dmcrypt, _vault_store, _get_hostname, _device_exists):
        store = _vault_store.return_value
        store.read.return_value = {'dmcrypt_key': 'testkey'}

        args = mock.MagicMock()
        args.uuid = ['passed-UUID']

        failures = (
            subprocess.CalledProcessError(
                returncode=1, cmd='cryptsetup open',
            ),
            subprocess.TimeoutExpired(cmd='cryptsetup open', timeout=300),
        )
        for failure in failures:
            with self.subTest(failure=failure):
                _dmcrypt.luks_open.side_effect = failure
                with self.assertRaises(exceptions.MapperOpenError):
                    shell._decrypt_block_device(
                        args, mock.MagicMock(), self.config,
                    )

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

    @mock.patch.object(shell.os.path, 'exists', return_value=True)
    def test_device_exists(self, _exists):
        self.assertTrue(shell._device_exists('test-uuid'))

        _exists.assert_called_once_with('/dev/mapper/crypt-test-uuid')

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

    @mock.patch('builtins.open', side_effect=OSError('no such file'))
    def test_read_existing_key_file_unreadable(self, _open):
        with self.assertRaises(exceptions.ExistingKeyInvalidError) as error:
            shell._read_existing_key('/path/to/key')

        self.assertIn('no such file', str(error.exception))

    @mock.patch.object(shell, 'sys')
    def test_read_existing_key_empty_is_invalid(self, _sys):
        _sys.stdin.isatty.return_value = False
        _sys.stdin.buffer.read.return_value = b''

        with self.assertRaises(exceptions.ExistingKeyInvalidError) as error:
            shell._read_existing_key(None)

        self.assertEqual(
            'Existing LUKS key cannot be empty',
            str(error.exception),
        )

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

    @mock.patch.object(shell, '_vault_client')
    def test_do_it_with_persistence_returns_result(
            self, _vault_client):
        args = mock.MagicMock()
        args.retry = 0
        func = mock.MagicMock(return_value={'luks_uuid': 'test-uuid'})

        result = shell._do_it_with_persistence(
            func, args, self.config,
        )

        self.assertEqual({'luks_uuid': 'test-uuid'}, result)
        func.assert_called_once_with(args, _vault_client.return_value,
                                     self.config)

    @mock.patch.object(shell, '_vault_client')
    def test_do_it_with_persistence_wraps_vault_connection_error(
            self, _vault_client):
        _vault_client.side_effect = hvac.exceptions.VaultDown('down')

        args = mock.MagicMock()
        args.retry = 0
        func = mock.MagicMock()

        with self.assertRaises(exceptions.VaultConnectionError):
            shell._do_it_with_persistence(func, args, self.config)

        func.assert_not_called()

    @mock.patch.object(shell.sys, 'argv',
                       ['vaultlocker', 'encrypt', '/dev/sdb'])
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'encrypt')
    def test_main_prints_json_result_on_success(
            self, _encrypt, _get_config):
        _get_config.return_value = self.config
        _encrypt.return_value = {
            'luks_uuid': 'test-uuid',
            'mapper_path': '/dev/mapper/crypt-test-uuid',
        }

        with mock.patch('builtins.print') as _print:
            shell.main()

        _print.assert_called_once_with(
            json.dumps({
                'luks_uuid': 'test-uuid',
                'mapper_path': '/dev/mapper/crypt-test-uuid',
            }),
        )

    @mock.patch.object(shell.sys, 'exit')
    @mock.patch.object(shell.sys, 'argv',
                       ['vaultlocker', 'encrypt', '/dev/sdb'])
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'encrypt')
    def test_main_handled_failure_exit_code(
            self, _encrypt, _get_config, _exit):
        """A controlled exception uses the handled-failure exit code."""
        _get_config.return_value = self.config
        _encrypt.side_effect = exceptions.LuksFormatError(
            '/dev/sdb', 'boom',
        )

        with mock.patch('builtins.print') as _print:
            shell.main()

        _exit.assert_called_once_with(ExitCode.HANDLED_FAILURE)
        printed = _print.call_args[0][0]
        self.assertEqual(
            {
                'error': "Can't operate on /dev/sdb. Error: boom",
            },
            json.loads(printed),
        )
        self.assertEqual(shell.sys.stderr, _print.call_args[1]['file'])

    @mock.patch.object(shell.sys, 'exit')
    @mock.patch.object(shell.sys, 'argv',
                       ['vaultlocker', 'enroll', '/dev/sdb'])
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'enroll')
    def test_main_handled_validation_failure_exit_code(
            self, _enroll, _get_config, _exit):
        _get_config.return_value = self.config
        _enroll.side_effect = exceptions.ExistingKeyInvalidError(
            'Existing key does not unlock /dev/sdb',
        )

        with mock.patch('builtins.print') as _print:
            shell.main()

        _exit.assert_called_once_with(ExitCode.HANDLED_FAILURE)
        printed = _print.call_args[0][0]
        self.assertEqual(
            {
                'error': 'Existing key does not unlock /dev/sdb',
            },
            json.loads(printed),
        )
        self.assertEqual(shell.sys.stderr, _print.call_args[1]['file'])

    @mock.patch.object(shell.sys, 'exit')
    @mock.patch.object(shell.sys, 'argv',
                       ['vaultlocker', 'encrypt', '/dev/sdb'])
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'encrypt')
    def test_main_configuration_failure_is_handled(
            self, _encrypt, _get_config, _exit):
        _get_config.side_effect = exceptions.ConfigurationError(
            'invalid configuration',
        )

        with mock.patch('builtins.print') as _print:
            shell.main()

        _encrypt.assert_not_called()
        _exit.assert_called_once_with(ExitCode.HANDLED_FAILURE)
        self.assertEqual(
            {
                'error': 'invalid configuration',
            },
            json.loads(_print.call_args[0][0]),
        )

    @mock.patch.object(shell.sys, 'argv',
                       ['vaultlocker', 'decrypt', 'test-uuid'])
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'decrypt')
    def test_failure_json_is_the_final_nonempty_stderr_line(
            self, _decrypt, _get_config):
        """Machine callers can ignore diagnostics and parse the final line."""
        _get_config.return_value = self.config

        def fail_after_diagnostic(*_args):
            print('DEBUG diagnostic', file=shell.sys.stderr)
            raise exceptions.ManagedKeyInvalidError(
                'vaultlocker-test/host/test-uuid',
            )

        _decrypt.side_effect = fail_after_diagnostic
        stderr = io.StringIO()

        with mock.patch.object(shell.sys, 'stderr', stderr):
            with self.assertRaises(SystemExit) as error:
                shell.main()

        self.assertEqual(ExitCode.HANDLED_FAILURE, error.exception.code)
        stderr_lines = [
            line for line in stderr.getvalue().splitlines() if line.strip()
        ]
        self.assertEqual('DEBUG diagnostic', stderr_lines[0])
        self.assertEqual(
            {
                'error': (
                    'Vault secret at vaultlocker-test/host/test-uuid '
                    'does not contain dmcrypt_key'
                ),
            },
            json.loads(stderr_lines[-1]),
        )

    @mock.patch.object(shell.sys, 'exit')
    @mock.patch.object(shell.sys, 'argv',
                       ['vaultlocker', 'encrypt', '/dev/sdb'])
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'encrypt')
    def test_main_unexpected_failure_exit_code(
            self, _encrypt, _get_config, _exit):
        """An unrecognized exception uses the unexpected-failure exit code."""
        _get_config.return_value = self.config
        _encrypt.side_effect = RuntimeError('unexpected')

        with mock.patch('builtins.print') as _print:
            shell.main()

        _exit.assert_called_once_with(ExitCode.UNEXPECTED_FAILURE)
        printed = _print.call_args[0][0]
        self.assertEqual(
            {
                'error': 'unexpected',
            },
            json.loads(printed),
        )
        self.assertEqual(shell.sys.stderr, _print.call_args[1]['file'])

    @mock.patch.object(shell.argparse.ArgumentParser, 'print_help')
    @mock.patch.object(shell.sys, 'argv', ['vaultlocker'])
    def test_main_no_subcommand_prints_help(self, _print_help):
        shell.main()

        _print_help.assert_called_once()

    @mock.patch.object(shell.sys, 'argv', ['vaultlocker', 'encrypt'])
    def test_main_usage_error_is_not_handled_failure_exit_code(self):
        """A CLI usage error must not be mistaken for a controlled result.

        argparse itself exits with status 2 on a missing required
        argument, before any of vaultlocker's own error handling runs.
        That must stay distinct from ``ExitCode.HANDLED_FAILURE``.
        """
        with self.assertRaises(SystemExit) as error:
            shell.main()

        self.assertEqual(2, error.exception.code)
        self.assertNotEqual(
            ExitCode.HANDLED_FAILURE, error.exception.code,
        )


class TestTenacityRetryBoundary(base.TestCase):
    """Tests which Vault failures are retried."""

    @mock.patch.object(shell, '_vault_client')
    def test_vault_down_is_retried_within_the_bound(
            self, _vault_client):
        _vault_client.side_effect = [
            hvac.exceptions.VaultDown('sealed'),
            mock.MagicMock(),
        ]

        args = mock.MagicMock()
        args.retry = 3
        func = mock.MagicMock(return_value={'luks_uuid': 'test-uuid'})

        result = shell._do_it_with_persistence(func, args, mock.MagicMock())

        self.assertEqual({'luks_uuid': 'test-uuid'}, result)
        self.assertEqual(2, _vault_client.call_count)
        func.assert_called_once()

    @mock.patch.object(shell, '_vault_client')
    def test_credential_failure_is_not_retried(self, _vault_client):
        _vault_client.side_effect = hvac.exceptions.Forbidden('bad creds')

        args = mock.MagicMock()
        # A long window shows that credential errors still fail immediately.
        args.retry = 10
        func = mock.MagicMock()

        with self.assertRaises(exceptions.VaultConnectionError):
            shell._do_it_with_persistence(func, args, mock.MagicMock())

        self.assertEqual(1, _vault_client.call_count)
        func.assert_not_called()

    @mock.patch.object(shell, '_vault_client')
    def test_unbounded_retry_still_fails_fast_on_credentials(
            self, _vault_client):
        """The default retry setting makes one attempt."""
        _vault_client.side_effect = hvac.exceptions.Forbidden('bad creds')

        args = mock.MagicMock()
        args.retry = -1
        func = mock.MagicMock()

        with self.assertRaises(exceptions.VaultConnectionError):
            shell._do_it_with_persistence(func, args, mock.MagicMock())

        self.assertEqual(1, _vault_client.call_count)
        func.assert_not_called()


class TestStoreAndValidateKey(base.TestCase):
    """Shared write-then-verify used by every path that stores a key."""

    def test_writes_and_confirms_the_key(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.return_value = {'dmcrypt_key': 'the-key'}

        shell._store_and_validate_key(store, 'host/uuid', 'the-key')

        store.write.assert_called_once_with(
            'host/uuid', {'dmcrypt_key': 'the-key'},
        )
        store.read.assert_called_once_with('host/uuid')

    def test_write_failure_is_reported(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.write.side_effect = hvac.exceptions.Forbidden('denied')

        with self.assertRaises(exceptions.VaultWriteError) as error:
            shell._store_and_validate_key(store, 'host/uuid', 'the-key')

        self.assertIn('vaultlocker-test/host/uuid', str(error.exception))

    def test_read_back_failure_is_reported(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.side_effect = hvac.exceptions.Forbidden('denied')

        with self.assertRaises(exceptions.VaultReadError) as error:
            shell._store_and_validate_key(store, 'host/uuid', 'the-key')

        self.assertIn('vaultlocker-test/host/uuid', str(error.exception))

    def test_malformed_read_back_is_reported(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.return_value = {'dmcrypt_key': ''}

        with self.assertRaises(
                exceptions.ManagedKeyInvalidError) as error:
            shell._store_and_validate_key(
                store, 'host/uuid', 'the-key',
            )

        self.assertIn('vaultlocker-test/host/uuid', str(error.exception))

    def test_mismatched_read_back_is_reported(self):
        """A mismatched key is rejected."""
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.return_value = {'dmcrypt_key': 'a-different-key'}

        with self.assertRaises(exceptions.VaultKeyMismatch) as error:
            shell._store_and_validate_key(store, 'host/uuid', 'the-key')

        self.assertIn('vaultlocker-test/host/uuid', str(error.exception))


class TestReadLuksUuid(base.TestCase):
    """Tests reading a device's LUKS UUID."""

    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_returns_uuid_for_existing_header(self, _luks_uuid):
        _luks_uuid.return_value = 'existing-uuid'

        self.assertEqual(
            'existing-uuid', shell._get_existing_luks_uuid('/dev/sdb'),
        )

    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_returns_none_for_the_no_header_exit_code(self, _luks_uuid):
        _luks_uuid.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd='cryptsetup luksUUID',
        )

        self.assertIsNone(shell._get_existing_luks_uuid('/dev/sdb'))

    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_other_error_codes_are_not_treated_as_plain(self, _luks_uuid):
        _luks_uuid.side_effect = subprocess.CalledProcessError(
            returncode=5, cmd='cryptsetup luksUUID',
        )

        with self.assertRaises(exceptions.LuksValidationError) as error:
            shell._get_existing_luks_uuid('/dev/sdb')

        self.assertIn('/dev/sdb', str(error.exception))

    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_timeout_is_not_treated_as_plain(self, _luks_uuid):
        _luks_uuid.side_effect = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=300,
        )

        with self.assertRaises(exceptions.LuksValidationError):
            shell._get_existing_luks_uuid('/dev/sdb')


class TestCanUnlockDevice(base.TestCase):
    """Tests checking whether a key unlocks a device."""

    @mock.patch.object(shell.dmcrypt, 'luks_test_key', return_value=True)
    def test_true_when_the_key_works(self, _luks_test_key):
        self.assertTrue(shell._key_unlocks_device('key', '/dev/sdb'))

    @mock.patch.object(shell.dmcrypt, 'luks_test_key', return_value=False)
    def test_false_when_the_key_does_not_work(self, _luks_test_key):
        self.assertFalse(shell._key_unlocks_device('key', '/dev/sdb'))

    @mock.patch.object(shell.dmcrypt, 'luks_test_key')
    def test_error_when_the_probe_itself_fails(self, _luks_test_key):
        _luks_test_key.side_effect = subprocess.CalledProcessError(
            returncode=-1, cmd='cryptsetup',
        )

        with self.assertRaises(exceptions.LuksValidationError):
            shell._key_unlocks_device('key', '/dev/sdb')

    @mock.patch.object(shell.dmcrypt, 'luks_test_key')
    def test_error_when_the_probe_times_out(self, _luks_test_key):
        _luks_test_key.side_effect = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=300,
        )

        with self.assertRaises(exceptions.LuksValidationError):
            shell._key_unlocks_device('key', '/dev/sdb')


class TestReadVaultKey(base.TestCase):
    """Tests reading Vault keys."""

    def test_none_when_nothing_stored(self):
        store = mock.MagicMock()
        store.read.side_effect = hvac.exceptions.InvalidPath('missing')

        self.assertIsNone(shell._read_vault_key(store, 'host/uuid'))

    def test_returns_stored_key(self):
        store = mock.MagicMock()
        store.read.return_value = {'dmcrypt_key': 'managed-key'}

        self.assertEqual(
            'managed-key',
            shell._read_vault_key(store, 'host/uuid'),
        )

    def test_rejects_malformed_data_without_overwriting(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.return_value = {'not-a-key': 'value'}

        with self.assertRaises(exceptions.ManagedKeyInvalidError) as error:
            shell._read_vault_key(store, 'host/uuid')

        self.assertIn('vaultlocker-test/host/uuid', str(error.exception))
        store.write.assert_not_called()
        store.delete.assert_not_called()

    def test_rejects_non_dict_data_without_overwriting(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.return_value = 'not-a-dict'

        with self.assertRaises(exceptions.ManagedKeyInvalidError):
            shell._read_vault_key(store, 'host/uuid')

        store.write.assert_not_called()


class TestEnsureVaultKey(base.TestCase):
    """Tests safely storing a Vault key."""

    def test_absent_key_is_written_and_verified(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.side_effect = [
            hvac.exceptions.InvalidPath('missing'),
            {'dmcrypt_key': 'expected-key'},
        ]

        shell._ensure_vault_key(
            store, 'host/uuid', 'expected-key',
        )

        store.write.assert_called_once_with(
            'host/uuid', {'dmcrypt_key': 'expected-key'},
        )

    def test_same_existing_key_is_reused_without_writing(self):
        store = mock.MagicMock()
        store.read.return_value = {'dmcrypt_key': 'expected-key'}

        shell._ensure_vault_key(
            store, 'host/uuid', 'expected-key',
        )

        store.write.assert_not_called()

    def test_different_existing_key_fails_without_writing(self):
        store = mock.MagicMock()
        store.mount_point = 'vaultlocker-test'
        store.read.return_value = {'dmcrypt_key': 'existing-key'}

        with self.assertRaises(exceptions.VaultKeyMismatch):
            shell._ensure_vault_key(
                store, 'host/uuid', 'expected-key',
            )

        store.write.assert_not_called()


class TestOpenAndRegisterDevice(base.TestCase):
    """Tests opening and registering a device."""

    @mock.patch.object(shell, '_register_boot_unlock')
    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'dmcrypt')
    def test_opens_mapper_when_missing(
            self, _dmcrypt, _device_exists, _register):
        result = shell._open_and_register_device(
            '/dev/sdb', 'test-uuid', 'the-key', '/path/to/conf',
        )

        _dmcrypt.luks_open.assert_called_once_with(
            'the-key', 'test-uuid', '/dev/sdb',
        )
        _register.assert_called_once_with(
            '/dev/sdb', 'test-uuid', '/path/to/conf',
        )
        self.assertEqual(
            {
                'luks_uuid': 'test-uuid',
                'mapper_path': '/dev/mapper/crypt-test-uuid',
            },
            result,
        )

    @mock.patch.object(shell, '_register_boot_unlock')
    @mock.patch.object(shell, '_device_exists', return_value=True)
    @mock.patch.object(shell, 'dmcrypt')
    def test_skips_opening_an_already_open_mapper(
            self, _dmcrypt, _device_exists, _register):
        """An open mapper is not opened again."""
        result = shell._open_and_register_device(
            '/dev/sdb', 'test-uuid', 'the-key', '/path/to/conf',
        )

        _dmcrypt.luks_open.assert_not_called()
        _register.assert_called_once_with(
            '/dev/sdb', 'test-uuid', '/path/to/conf',
        )
        self.assertEqual('test-uuid', result['luks_uuid'])

    @mock.patch.object(shell, '_device_exists', return_value=False)
    @mock.patch.object(shell, 'dmcrypt')
    def test_mapper_open_failure_is_reported(self, _dmcrypt, _device_exists):
        _dmcrypt.luks_open.side_effect = subprocess.CalledProcessError(
            returncode=-1, cmd='cryptsetup',
        )

        with self.assertRaises(exceptions.MapperOpenError):
            shell._open_and_register_device(
                '/dev/sdb', 'test-uuid', 'the-key', '/path/to/conf',
            )


class TestReuseEncryptedDevice(base.TestCase):
    """Tests reusing an encrypted device."""

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_key_unlocks_device', return_value=True)
    @mock.patch.object(shell, '_read_vault_key')
    @mock.patch.object(shell, '_vault_store')
    def test_reuses_when_the_managed_key_works(
            self, _vault_store, _read_vault_key, _key_unlocks_device,
            _open_and_register):
        _read_vault_key.return_value = 'managed-key'
        _open_and_register.return_value = {'luks_uuid': 'existing-uuid'}

        args = mock.MagicMock()
        args.uuid = None
        args.config = '/path/to/conf'

        result = shell._open_existing_managed_device(
            args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
            'existing-uuid',
        )

        _key_unlocks_device.assert_called_once_with('managed-key', '/dev/sdb')
        _open_and_register.assert_called_once_with(
            '/dev/sdb', 'existing-uuid', 'managed-key', '/path/to/conf',
        )
        self.assertEqual({'luks_uuid': 'existing-uuid'}, result)

    @mock.patch.object(shell, '_vault_store')
    def test_rejects_a_uuid_that_does_not_match_the_device(
            self, _vault_store):
        args = mock.MagicMock()
        args.uuid = 'requested-uuid'

        with self.assertRaises(exceptions.LuksValidationError):
            shell._open_existing_managed_device(
                args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
                'existing-uuid',
            )

        _vault_store.assert_not_called()

    @mock.patch.object(shell, '_read_vault_key', return_value=None)
    @mock.patch.object(shell, '_vault_store')
    def test_refuses_a_device_with_no_managed_key(
            self, _vault_store, _read_vault_key):
        """An unmanaged device is not reformatted."""
        args = mock.MagicMock()
        args.uuid = None

        with self.assertRaises(exceptions.LuksValidationError) as error:
            shell._open_existing_managed_device(
                args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
                'existing-uuid',
            )

        self.assertIn('no', str(error.exception))

    @mock.patch.object(shell, '_key_unlocks_device', return_value=False)
    @mock.patch.object(shell, '_read_vault_key')
    @mock.patch.object(shell, '_vault_store')
    def test_refuses_a_managed_key_that_does_not_unlock_it(
            self, _vault_store, _read_vault_key, _key_unlocks_device):
        _read_vault_key.return_value = 'wrong-key'

        args = mock.MagicMock()
        args.uuid = None

        with self.assertRaises(exceptions.LuksValidationError):
            shell._open_existing_managed_device(
                args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
                'existing-uuid',
            )


class TestFormatCompleted(base.TestCase):
    """Tests checking a failed format."""

    @mock.patch.object(shell, '_key_unlocks_device', return_value=True)
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='the-uuid')
    def test_true_when_uuid_and_key_both_match(self, _luks_uuid,
                                               _key_unlocks_device):
        self.assertTrue(
            shell._format_completed('/dev/sdb', 'the-uuid', 'the-key'),
        )

    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_false_when_the_device_cannot_be_inspected(self, _luks_uuid):
        _luks_uuid.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd='cryptsetup',
        )

        self.assertFalse(
            shell._format_completed('/dev/sdb', 'the-uuid', 'the-key'),
        )

    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='other-uuid')
    def test_false_when_the_uuid_does_not_match(self, _luks_uuid):
        self.assertFalse(
            shell._format_completed('/dev/sdb', 'the-uuid', 'the-key'),
        )

    @mock.patch.object(shell, '_key_unlocks_device', return_value=False)
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='the-uuid')
    def test_false_when_the_key_does_not_unlock_it(
            self, _luks_uuid, _key_unlocks_device):
        self.assertFalse(
            shell._format_completed('/dev/sdb', 'the-uuid', 'the-key'),
        )


class TestFormatDevice(base.TestCase):
    """Tests formatting a plain device."""

    @mock.patch.object(shell.dmcrypt, 'luks_format')
    @mock.patch.object(shell, '_vault_store')
    def test_different_existing_key_prevents_write_and_format(
            self, _vault_store, _luks_format):
        store = _vault_store.return_value
        store.mount_point = 'vaultlocker-test'
        store.read.return_value = {'dmcrypt_key': 'existing-key'}

        args = mock.MagicMock()

        with self.assertRaises(exceptions.VaultKeyMismatch):
            shell._format_device(
                args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
                'new-uuid', 'expected-key',
            )

        store.write.assert_not_called()
        _luks_format.assert_not_called()

    @mock.patch.object(shell.dmcrypt, 'luks_format')
    @mock.patch.object(shell, '_vault_store')
    def test_malformed_existing_key_prevents_write_and_format(
            self, _vault_store, _luks_format):
        store = _vault_store.return_value
        store.mount_point = 'vaultlocker-test'

        malformed_data = (
            'not-a-mapping',
            {},
            {'dmcrypt_key': ''},
        )
        for stored_data in malformed_data:
            with self.subTest(stored_data=stored_data):
                store.read.return_value = stored_data
                with self.assertRaises(exceptions.ManagedKeyInvalidError):
                    shell._format_device(
                        mock.MagicMock(), mock.MagicMock(),
                        mock.MagicMock(), '/dev/sdb', 'new-uuid',
                        'expected-key',
                    )

        store.write.assert_not_called()
        _luks_format.assert_not_called()

    @mock.patch.object(
        shell.boot_unlock, 'running_in_snap', return_value=False,
    )
    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_ensure_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'udevadm_settle')
    @mock.patch.object(shell.dmcrypt, 'udevadm_rescan')
    @mock.patch.object(shell.dmcrypt, 'luks_format')
    def test_formats_stores_key_first_and_completes(
            self, _luks_format, _udevadm_rescan, _udevadm_settle,
            _vault_store, _ensure_vault_key, _open_and_register,
            _running_in_snap):
        _open_and_register.return_value = {'luks_uuid': 'new-uuid'}

        args = mock.MagicMock()
        args.config = '/path/to/conf'

        result = shell._format_device(
            args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
            'new-uuid', 'new-key',
        )

        _ensure_vault_key.assert_called_once_with(
            _vault_store.return_value, mock.ANY, 'new-key',
        )
        _luks_format.assert_called_once_with('new-key', '/dev/sdb',
                                             'new-uuid')
        _udevadm_rescan.assert_called_once_with('/dev/sdb')
        _udevadm_settle.assert_called_once_with('new-uuid')
        _open_and_register.assert_called_once_with(
            '/dev/sdb', 'new-uuid', 'new-key', '/path/to/conf',
        )
        self.assertEqual({'luks_uuid': 'new-uuid'}, result)

    @mock.patch.object(shell.boot_unlock, 'running_in_snap',
                       return_value=True)
    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_ensure_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'udevadm_settle')
    @mock.patch.object(shell.dmcrypt, 'udevadm_rescan')
    @mock.patch.object(shell.dmcrypt, 'luks_format')
    def test_format_skips_udev_in_snap(
            self, _luks_format, _udevadm_rescan, _udevadm_settle,
            _vault_store, _ensure_vault_key, _open_and_register,
            _running_in_snap):
        args = mock.MagicMock()
        args.config = '/path/to/conf'

        shell._format_device(
            args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
            'new-uuid', 'new-key',
        )

        _luks_format.assert_called_once_with(
            'new-key', '/dev/sdb', 'new-uuid',
        )
        _udevadm_rescan.assert_not_called()
        _udevadm_settle.assert_not_called()
        _open_and_register.assert_called_once_with(
            '/dev/sdb', 'new-uuid', 'new-key', '/path/to/conf',
        )

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_format_completed', return_value=True)
    @mock.patch.object(shell, '_ensure_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'udevadm_settle')
    @mock.patch.object(shell.dmcrypt, 'udevadm_rescan')
    @mock.patch.object(shell.dmcrypt, 'luks_format')
    def test_timeout_that_actually_completed_is_not_fatal(
            self, _luks_format, _udevadm_rescan, _udevadm_settle,
            _vault_store, _ensure_vault_key, _format_completed,
            _open_and_register):
        """A completed format survives a timeout."""
        _luks_format.side_effect = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=300,
        )
        _open_and_register.return_value = {'luks_uuid': 'new-uuid'}

        args = mock.MagicMock()
        args.config = '/path/to/conf'

        result = shell._format_device(
            args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
            'new-uuid', 'new-key',
        )

        _format_completed.assert_called_once_with(
            '/dev/sdb', 'new-uuid', 'new-key',
        )
        _open_and_register.assert_called_once_with(
            '/dev/sdb', 'new-uuid', 'new-key', '/path/to/conf',
        )
        self.assertEqual({'luks_uuid': 'new-uuid'}, result)

    @mock.patch.object(shell, '_format_completed', return_value=False)
    @mock.patch.object(shell, '_ensure_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_format')
    def test_genuine_format_failure_preserves_the_vault_key(
            self, _luks_format, _vault_store, _ensure_vault_key,
            _format_completed):
        """The Vault key must survive a genuine format failure.

        It must never be deleted once luksFormat may have started: it
        may be the only thing that can unlock the device.
        """
        _luks_format.side_effect = subprocess.CalledProcessError(
            returncode=-1, cmd='cryptsetup',
        )

        args = mock.MagicMock()
        args.config = '/path/to/conf'

        with self.assertRaises(exceptions.LuksFormatError):
            shell._format_device(
                args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
                'new-uuid', 'new-key',
            )

        store = _vault_store.return_value
        store.delete.assert_not_called()

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_ensure_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'udevadm_settle')
    @mock.patch.object(shell.dmcrypt, 'udevadm_rescan')
    @mock.patch.object(shell.dmcrypt, 'luks_format')
    def test_udev_failure_is_not_fatal(
            self, _luks_format, _udevadm_rescan, _udevadm_settle,
            _vault_store, _ensure_vault_key, _open_and_register):
        _udevadm_rescan.side_effect = subprocess.CalledProcessError(
            returncode=-1, cmd='udevadm',
        )
        _open_and_register.return_value = {'luks_uuid': 'new-uuid'}

        args = mock.MagicMock()
        args.config = '/path/to/conf'

        result = shell._format_device(
            args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
            'new-uuid', 'new-key',
        )

        self.assertEqual({'luks_uuid': 'new-uuid'}, result)

    @mock.patch.object(shell.os.path, 'exists', return_value=True)
    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_ensure_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'udevadm_settle')
    @mock.patch.object(shell.dmcrypt, 'udevadm_rescan')
    @mock.patch.object(shell.dmcrypt, 'luks_format')
    def test_udev_failure_with_existing_symlink_is_quiet(
            self, _luks_format, _udevadm_rescan, _udevadm_settle,
            _vault_store, _ensure_vault_key, _open_and_register, _exists):
        _udevadm_rescan.side_effect = subprocess.CalledProcessError(
            returncode=-1, cmd='udevadm',
        )
        _open_and_register.return_value = {'luks_uuid': 'new-uuid'}

        args = mock.MagicMock()
        args.config = '/path/to/conf'

        result = shell._format_device(
            args, mock.MagicMock(), mock.MagicMock(), '/dev/sdb',
            'new-uuid', 'new-key',
        )

        self.assertEqual({'luks_uuid': 'new-uuid'}, result)


class TestEncryptBlockDevice(base.TestCase):
    """Tests choosing between reuse and format."""

    @mock.patch.object(shell, '_format_device')
    @mock.patch.object(shell, '_open_existing_managed_device')
    @mock.patch.object(shell, '_get_existing_luks_uuid', return_value=None)
    def test_dispatches_to_format_when_plain(
            self, _read_uuid, _reuse, _format_device):
        _format_device.return_value = {'luks_uuid': 'new-uuid'}

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        result = shell._encrypt_block_device(
            args, mock.MagicMock(), mock.MagicMock(),
            new_uuid='new-uuid', new_key='new-key',
        )

        _reuse.assert_not_called()
        _format_device.assert_called_once_with(
            args, mock.ANY, mock.ANY, '/dev/sdb',
            'new-uuid', 'new-key',
        )
        self.assertEqual({'luks_uuid': 'new-uuid'}, result)

    @mock.patch.object(shell, '_format_device')
    @mock.patch.object(shell, '_open_existing_managed_device')
    @mock.patch.object(shell, '_get_existing_luks_uuid',
                       return_value='existing-uuid')
    def test_dispatches_to_reuse_when_already_luks(
            self, _read_uuid, _reuse, _format_device):
        _reuse.return_value = {'luks_uuid': 'existing-uuid'}

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        result = shell._encrypt_block_device(
            args, mock.MagicMock(), mock.MagicMock(),
            new_uuid='new-uuid', new_key='new-key',
        )

        _format_device.assert_not_called()
        _reuse.assert_called_once_with(
            args, mock.ANY, mock.ANY, '/dev/sdb', 'existing-uuid',
        )
        self.assertEqual({'luks_uuid': 'existing-uuid'}, result)


class TestEncryptHandler(base.TestCase):
    """Tests the encrypt handler."""

    @mock.patch.object(shell, '_do_it_with_persistence')
    @mock.patch.object(shell.dmcrypt, 'generate_key',
                       return_value='generated-key')
    @mock.patch.object(shell.uuid, 'uuid4', return_value='generated-uuid')
    def test_generates_a_uuid_when_none_was_requested(
            self, _uuid4, _generate_key, _do):
        args = mock.MagicMock()
        args.uuid = None
        config = mock.MagicMock()

        shell.encrypt(args, config)

        _uuid4.assert_called_once()
        operation = _do.call_args[0][0]
        self.assertEqual(
            'generated-uuid', operation.keywords['new_uuid'],
        )
        self.assertEqual(
            'generated-key', operation.keywords['new_key'],
        )

    @mock.patch.object(shell, '_do_it_with_persistence')
    @mock.patch.object(shell.dmcrypt, 'generate_key',
                       return_value='generated-key')
    @mock.patch.object(shell.uuid, 'uuid4')
    def test_uses_the_requested_uuid_without_generating_one(
            self, _uuid4, _generate_key, _do):
        args = mock.MagicMock()
        args.uuid = 'requested-uuid'
        config = mock.MagicMock()

        shell.encrypt(args, config)

        _uuid4.assert_not_called()
        operation = _do.call_args[0][0]
        self.assertEqual(
            'requested-uuid', operation.keywords['new_uuid'],
        )

    @mock.patch.object(shell, '_encrypt_block_device')
    @mock.patch.object(shell, '_vault_client')
    @mock.patch.object(shell.dmcrypt, 'generate_key',
                       return_value='generated-key')
    @mock.patch.object(shell.uuid, 'uuid4', return_value='generated-uuid')
    def test_new_uuid_and_key_are_stable_across_internal_retries(
            self, _uuid4, _generate_key, _vault_client,
            _encrypt_impl):
        """Retries keep the same UUID and key."""
        _vault_client.return_value = mock.MagicMock()
        _encrypt_impl.side_effect = [
            hvac.exceptions.VaultDown('sealed'),
            {
                'luks_uuid': 'generated-uuid',
                'mapper_path': '/dev/mapper/crypt-generated-uuid',
            },
        ]

        args = mock.MagicMock()
        args.uuid = None
        args.retry = 3
        config = mock.MagicMock()

        result = shell.encrypt(args, config)

        _uuid4.assert_called_once()
        _generate_key.assert_called_once()
        self.assertEqual(2, _encrypt_impl.call_count)
        for call in _encrypt_impl.call_args_list:
            self.assertEqual(
                'generated-uuid', call.kwargs['new_uuid'],
            )
            self.assertEqual('generated-key', call.kwargs['new_key'])
        self.assertEqual('generated-uuid', result['luks_uuid'])


class TestEnrollBlockDevice(base.TestCase):
    """Tests adding or reusing a Vault key."""

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_read_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_succeeds_without_the_original_credential_when_already_enrolled(
            self, _luks_uuid, _vault_store, _read_vault_key,
            _open_and_register):
        """A repeated enrollment does not need the current key."""
        _read_vault_key.return_value = 'managed-key'
        _open_and_register.return_value = {'luks_uuid': 'test-uuid'}

        get_operator_key = mock.MagicMock(
            side_effect=AssertionError('credential should not be read'),
        )

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        args.config = '/path/to/conf'

        with mock.patch.object(
                shell, '_key_unlocks_device', return_value=True,
        ) as key_check:
            result = shell._enroll_block_device(
                args, mock.MagicMock(), mock.MagicMock(), get_operator_key,
            )

        get_operator_key.assert_not_called()
        key_check.assert_called_once_with('managed-key', '/dev/sdb')
        _open_and_register.assert_called_once_with(
            '/dev/sdb', 'test-uuid', 'managed-key', '/path/to/conf',
        )
        self.assertEqual({'luks_uuid': 'test-uuid'}, result)

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_store_and_validate_key')
    @mock.patch.object(shell, '_read_vault_key', return_value=None)
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_add_key')
    @mock.patch.object(shell.dmcrypt, 'generate_key',
                       return_value='new-managed-key')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_generates_and_adds_a_managed_key_when_none_exists(
            self, _luks_uuid, _generate_key, _luks_add_key, _vault_store,
            _read_vault_key, _store_and_validate_key, _open_and_register):
        _open_and_register.return_value = {'luks_uuid': 'test-uuid'}
        get_operator_key = mock.MagicMock(return_value=b'existing-key')

        def can_unlock(key, device):
            return key == b'existing-key' or key == 'new-managed-key'

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        args.config = '/path/to/conf'

        with mock.patch.object(
                shell, '_key_unlocks_device',
                side_effect=can_unlock,
        ) as key_check:
            result = shell._enroll_block_device(
                args, mock.MagicMock(), mock.MagicMock(), get_operator_key,
            )

        get_operator_key.assert_called_once()
        _store_and_validate_key.assert_called_once_with(
            _vault_store.return_value, mock.ANY, 'new-managed-key',
        )
        _luks_add_key.assert_called_once_with(
            b'existing-key', 'new-managed-key', '/dev/sdb',
        )
        _open_and_register.assert_called_once_with(
            '/dev/sdb', 'test-uuid', 'new-managed-key', '/path/to/conf',
        )
        self.assertEqual({'luks_uuid': 'test-uuid'}, result)
        self.assertEqual(2, key_check.call_count)

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_store_and_validate_key')
    @mock.patch.object(shell, '_read_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_add_key')
    @mock.patch.object(shell.dmcrypt, 'generate_key')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_reuses_a_pre_provisioned_managed_key_instead_of_replacing_it(
            self, _luks_uuid, _generate_key, _luks_add_key, _vault_store,
            _read_vault_key, _store_and_validate_key, _open_and_register):
        """A saved Vault key is reused."""
        _read_vault_key.return_value = 'pre-provisioned-key'
        _open_and_register.return_value = {'luks_uuid': 'test-uuid'}
        get_operator_key = mock.MagicMock(return_value=b'existing-key')

        # Check before and after adding the key.
        unlock_results = [False, True, True]

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        args.config = '/path/to/conf'

        with mock.patch.object(
                shell, '_key_unlocks_device',
                side_effect=unlock_results):
            shell._enroll_block_device(
                args, mock.MagicMock(), mock.MagicMock(), get_operator_key,
            )

        _generate_key.assert_not_called()
        _store_and_validate_key.assert_not_called()
        _luks_add_key.assert_called_once_with(
            b'existing-key', 'pre-provisioned-key', '/dev/sdb',
        )

    @mock.patch.object(shell.dmcrypt, 'luks_add_key')
    @mock.patch.object(shell.dmcrypt, 'luks_test_key')
    @mock.patch.object(shell, '_read_vault_key', return_value='managed-key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_inconclusive_managed_key_probe_does_not_add_another_key(
            self, _luks_uuid, _vault_store, _read_vault_key,
            _luks_test_key, _luks_add_key):
        _luks_test_key.side_effect = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=300,
        )
        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        get_operator_key = mock.MagicMock(return_value=b'existing-key')

        with self.assertRaises(exceptions.LuksValidationError):
            shell._enroll_block_device(
                args, mock.MagicMock(), mock.MagicMock(), get_operator_key,
            )

        get_operator_key.assert_not_called()
        _luks_add_key.assert_not_called()

    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_uuid_lookup_failure_is_reported_before_touching_vault(
            self, _luks_uuid, _vault_store):
        _luks_uuid.side_effect = subprocess.CalledProcessError(
            returncode=-1, cmd='cryptsetup',
        )

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        with self.assertRaises(exceptions.LuksValidationError):
            shell._enroll_block_device(
                args, mock.MagicMock(), mock.MagicMock(),
                mock.MagicMock(),
            )

        _vault_store.assert_not_called()

    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_uuid_lookup_timeout_is_reported_before_touching_vault(
            self, _luks_uuid, _vault_store):
        _luks_uuid.side_effect = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=300,
        )

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        with self.assertRaises(exceptions.LuksValidationError):
            shell._enroll_block_device(
                args, mock.MagicMock(), mock.MagicMock(),
                mock.MagicMock(),
            )

        _vault_store.assert_not_called()

    @mock.patch.object(shell, '_read_vault_key', return_value=None)
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_rejects_an_existing_credential_that_does_not_unlock_it(
            self, _luks_uuid, _vault_store, _read_vault_key):
        get_operator_key = mock.MagicMock(return_value=b'wrong-key')

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        with mock.patch.object(
                shell, '_key_unlocks_device', return_value=False,
        ):
            with self.assertRaises(
                    exceptions.ExistingKeyInvalidError) as error:
                shell._enroll_block_device(
                    args, mock.MagicMock(), mock.MagicMock(),
                    get_operator_key,
                )

        self.assertEqual(
            'Existing key does not unlock /dev/sdb',
            str(error.exception),
        )
        get_operator_key.assert_called_once()

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_store_and_validate_key')
    @mock.patch.object(shell, '_read_vault_key', return_value=None)
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_add_key')
    @mock.patch.object(shell.dmcrypt, 'generate_key',
                       return_value='new-managed-key')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_add_key_timeout_that_actually_completed_is_not_fatal(
            self, _luks_uuid, _generate_key, _luks_add_key, _vault_store,
            _read_vault_key, _store_and_validate_key, _open_and_register):
        """A completed key addition survives a timeout."""
        _luks_add_key.side_effect = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=300,
        )
        _open_and_register.return_value = {'luks_uuid': 'test-uuid'}
        get_operator_key = mock.MagicMock(return_value=b'existing-key')

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        args.config = '/path/to/conf'

        with mock.patch.object(
                shell, '_key_unlocks_device', return_value=True,
        ):
            result = shell._enroll_block_device(
                args, mock.MagicMock(), mock.MagicMock(), get_operator_key,
            )

        self.assertEqual({'luks_uuid': 'test-uuid'}, result)

    @mock.patch.object(shell, '_store_and_validate_key')
    @mock.patch.object(shell, '_read_vault_key', return_value=None)
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_add_key')
    @mock.patch.object(shell.dmcrypt, 'generate_key',
                       return_value='new-managed-key')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_add_key_failure_preserves_the_managed_key(
            self, _luks_uuid, _generate_key, _luks_add_key, _vault_store,
            _read_vault_key, _store_and_validate_key):
        _luks_add_key.side_effect = subprocess.CalledProcessError(
            returncode=-1, cmd='cryptsetup',
        )
        get_operator_key = mock.MagicMock(return_value=b'existing-key')

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        def can_unlock(key, device):
            return key == b'existing-key'

        with mock.patch.object(
                shell, '_key_unlocks_device',
                side_effect=can_unlock):
            with self.assertRaises(exceptions.LuksAddKeyError):
                shell._enroll_block_device(
                    args, mock.MagicMock(), mock.MagicMock(),
                    get_operator_key,
                )

        store = _vault_store.return_value
        store.delete.assert_not_called()

    @mock.patch.object(shell, '_store_and_validate_key')
    @mock.patch.object(shell, '_read_vault_key', return_value=None)
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_add_key')
    @mock.patch.object(shell.dmcrypt, 'generate_key',
                       return_value='new-managed-key')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid', return_value='test-uuid')
    def test_add_key_that_silently_did_not_take_is_reported(
            self, _luks_uuid, _generate_key, _luks_add_key, _vault_store,
            _read_vault_key, _store_and_validate_key):
        """An ineffective key addition is rejected."""
        get_operator_key = mock.MagicMock(return_value=b'existing-key')

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']

        def can_unlock(key, device):
            return key == b'existing-key'

        with mock.patch.object(
                shell, '_key_unlocks_device',
                side_effect=can_unlock):
            with self.assertRaises(exceptions.LuksAddKeyError):
                shell._enroll_block_device(
                    args, mock.MagicMock(), mock.MagicMock(),
                    get_operator_key,
                )

        _luks_add_key.assert_called_once()


class TestEnrollHandler(base.TestCase):
    """Tests the enroll handler."""

    @mock.patch.object(shell, '_do_it_with_persistence')
    @mock.patch.object(shell, '_read_existing_key', return_value=b'secret')
    def test_credential_is_cached_across_repeated_use(
            self, _read_existing_key, _do):
        args = mock.MagicMock()
        args.existing_key_file = '/path/to/key'
        config = mock.MagicMock()

        shell.enroll(args, config)

        operation = _do.call_args[0][0]
        get_operator_key = operation.keywords['get_operator_key']

        # Repeated reads use the cached key.
        first = get_operator_key()
        second = get_operator_key()

        self.assertEqual(b'secret', first)
        self.assertEqual(b'secret', second)
        _read_existing_key.assert_called_once_with('/path/to/key')

    @mock.patch.object(shell, '_do_it_with_persistence')
    @mock.patch.object(shell, '_read_existing_key')
    def test_credential_is_never_read_when_not_needed(
            self, _read_existing_key, _do):
        args = mock.MagicMock()
        args.existing_key_file = None
        config = mock.MagicMock()

        shell.enroll(args, config)

        # The mocked operation does not request the current key.
        _read_existing_key.assert_not_called()


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
        with self.assertRaises(exceptions.ConfigurationError) as error:
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


class TestHandlersAndConfig(base.TestCase):
    """Coverage for the thin CLI handlers and config loading."""

    @mock.patch.object(shell, '_do_it_with_persistence')
    def test_encrypt_handler_delegates(self, _do):
        _do.return_value = {'luks_uuid': 'test-uuid'}
        args = mock.MagicMock()
        args.uuid = 'passed-uuid'
        config = mock.MagicMock()

        with mock.patch.object(shell.dmcrypt, 'generate_key',
                               return_value='key'):
            result = shell.encrypt(args, config)

        operation = _do.call_args[0][0]
        self.assertIs(shell._encrypt_block_device, operation.func)
        self.assertEqual('passed-uuid', operation.keywords['new_uuid'])
        self.assertIs(args, _do.call_args[0][1])
        self.assertIs(config, _do.call_args[0][2])
        self.assertEqual({'luks_uuid': 'test-uuid'}, result)

    @mock.patch.object(shell, '_do_it_with_persistence')
    def test_enroll_handler_delegates(self, _do):
        _do.return_value = {'luks_uuid': 'test-uuid'}
        args = mock.MagicMock()
        args.existing_key_file = '/path/to/key'
        config = mock.MagicMock()

        result = shell.enroll(args, config)

        operation = _do.call_args[0][0]
        self.assertIs(shell._enroll_block_device, operation.func)
        self.assertTrue(callable(operation.keywords['get_operator_key']))
        self.assertIs(args, _do.call_args[0][1])
        self.assertIs(config, _do.call_args[0][2])
        self.assertEqual({'luks_uuid': 'test-uuid'}, result)

    @mock.patch.object(shell, '_do_it_with_persistence')
    def test_decrypt_handler_delegates(self, _do):
        _do.return_value = None
        args = mock.MagicMock()
        config = mock.MagicMock()

        result = shell.decrypt(args, config)

        _do.assert_called_once_with(
            shell._decrypt_block_device, args, config,
        )
        self.assertIsNone(result)

    def test_get_config_reads_and_validates_existing_file(self):
        contents = """[vault]
url = https://vault.example
approle = role-id
secret_id = secret-id
backend = vaultlocker
kv_version = 2
"""
        with mock.patch(
                'builtins.open', mock.mock_open(read_data=contents)) as _open:
            config = shell.get_config('/path/to/conf')

        _open.assert_called_once_with('/path/to/conf', 'r')
        self.assertIsInstance(config, shell.configparser.ConfigParser)
        self.assertEqual('2', config.get('vault', 'kv_version'))

    @mock.patch('builtins.open', side_effect=FileNotFoundError('missing'))
    def test_get_config_missing_file_is_controlled(self, _open):
        with self.assertRaises(exceptions.ConfigurationError) as error:
            shell.get_config('/path/to/conf')

        self.assertIn(
            'Unable to load configuration /path/to/conf',
            str(error.exception),
        )

    def test_get_config_malformed_file_is_controlled(self):
        with mock.patch(
                'builtins.open',
                mock.mock_open(read_data='not an ini file')):
            with self.assertRaises(exceptions.ConfigurationError):
                shell.get_config('/path/to/conf')

    def test_get_config_missing_required_option_is_controlled(self):
        contents = """[vault]
url = https://vault.example
approle = role-id
secret_id = secret-id
"""
        with mock.patch(
                'builtins.open', mock.mock_open(read_data=contents)):
            with self.assertRaises(exceptions.ConfigurationError):
                shell.get_config('/path/to/conf')

    def test_get_config_empty_required_option_is_controlled(self):
        contents = """[vault]
url = https://vault.example
approle = role-id
secret_id = secret-id
backend =
"""
        with mock.patch(
                'builtins.open', mock.mock_open(read_data=contents)):
            with self.assertRaises(exceptions.ConfigurationError):
                shell.get_config('/path/to/conf')

    def test_get_config_invalid_kv_version_is_controlled(self):
        contents = """[vault]
url = https://vault.example
approle = role-id
secret_id = secret-id
backend = vaultlocker
kv_version = 3
"""
        with mock.patch(
                'builtins.open', mock.mock_open(read_data=contents)):
            with self.assertRaises(exceptions.ConfigurationError):
                shell.get_config('/path/to/conf')


class TestSubprocessTimeouts(base.TestCase):
    """Cryptsetup timeouts are handled the same as ordinary failures."""

    @mock.patch.object(shell, '_open_and_register_device')
    @mock.patch.object(shell, '_ensure_vault_key')
    @mock.patch.object(shell, '_vault_store')
    @mock.patch.object(shell.dmcrypt, 'luks_uuid')
    def test_encrypt_format_timeout_that_did_not_complete_fails(
            self, _luks_uuid, _vault_store, _ensure_vault_key,
            _open_and_register):
        _luks_uuid.side_effect = [
            subprocess.CalledProcessError(
                returncode=1, cmd='cryptsetup luksUUID',
            ),
            subprocess.TimeoutExpired(cmd='cryptsetup', timeout=300),
        ]

        args = mock.MagicMock()
        args.block_device = ['/dev/sdb']
        args.config = '/path/to/conf'

        with mock.patch.object(shell.dmcrypt, 'luks_format') as _format:
            _format.side_effect = subprocess.TimeoutExpired(
                cmd='cryptsetup', timeout=300,
            )

            with self.assertRaises(exceptions.LuksFormatError):
                shell._encrypt_block_device(
                    args, mock.MagicMock(), mock.MagicMock(),
                    new_uuid='passed-UUID', new_key='testkey',
                )

        _open_and_register.assert_not_called()
        store = _vault_store.return_value
        store.delete.assert_not_called()

    @mock.patch.object(shell, '_vault_store')
    def test_enroll_validation_timeout_is_reported(self, _vault_store):
        with mock.patch.object(shell.dmcrypt, 'luks_uuid') as _luks_uuid:
            _luks_uuid.side_effect = subprocess.TimeoutExpired(
                cmd='cryptsetup', timeout=300,
            )

            args = mock.MagicMock()
            args.block_device = ['/dev/sdb']

            with self.assertRaises(exceptions.LuksValidationError):
                shell._enroll_block_device(
                    args, mock.MagicMock(), mock.MagicMock(),
                    mock.MagicMock(),
                )

        _vault_store.assert_not_called()


class TestSubprocessErrorHelpers(base.TestCase):

    def test_output_prefers_captured_output(self):
        error = subprocess.CalledProcessError(
            returncode=1, cmd='cryptsetup', output=b'boom',
        )
        self.assertEqual(b'boom', shell._subprocess_error_output(error))

    def test_output_falls_back_to_stderr(self):
        error = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=1, stderr=b'stderr-text',
        )
        self.assertEqual(b'stderr-text', shell._subprocess_error_output(error))

    def test_output_falls_back_to_string(self):
        error = subprocess.TimeoutExpired(cmd='cryptsetup', timeout=1)
        self.assertEqual(str(error), shell._subprocess_error_output(error))

    def test_returncode(self):
        error = subprocess.CalledProcessError(returncode=3, cmd='x')
        self.assertEqual(3, shell._subprocess_error_returncode(error))

        timeout = subprocess.TimeoutExpired(cmd='x', timeout=1)
        self.assertIsNone(shell._subprocess_error_returncode(timeout))


class TestRegisterBootUnlock(base.TestCase):
    """Tests for boot-unlock registration failure classification."""

    @mock.patch.object(shell, 'boot_unlock')
    def test_registers_boot_unlock(self, _boot_unlock):
        shell._register_boot_unlock('/dev/sdb', 'test-uuid', '/cfg')

        _boot_unlock.register.assert_called_once_with('test-uuid', '/cfg')

    @mock.patch.object(shell, 'boot_unlock')
    def test_wraps_failure_as_boot_config_error(self, _boot_unlock):
        _boot_unlock.register.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd='pebble',
        )

        with self.assertRaises(exceptions.BootConfigError):
            shell._register_boot_unlock('/dev/sdb', 'test-uuid', '/cfg')
