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

import json

from unittest import mock

import hvac

from vaultlocker import exceptions
from vaultlocker.exit_codes import ExitCode
from vaultlocker import shell
from vaultlocker.tests.unit import base


class TestCommandResults(base.TestCase):

    @mock.patch.object(shell.sys, 'argv', [
        'vaultlocker', 'encrypt', '/dev/sdb',
    ])
    @mock.patch('builtins.print')
    @mock.patch.object(shell, 'get_config')
    @mock.patch.object(shell, 'encrypt')
    def test_main_prints_json_result(self, encrypt, get_config, print_):
        result = {
            'luks_uuid': 'test-uuid',
            'mapper_path': '/dev/mapper/crypt-test-uuid',
        }
        encrypt.return_value = result

        shell.main()

        print_.assert_called_once_with(json.dumps(result))

    @mock.patch.object(shell.sys, 'argv', [
        'vaultlocker', 'encrypt', '/dev/sdb',
    ])
    @mock.patch('builtins.print')
    @mock.patch.object(shell, 'get_config')
    def test_main_returns_handled_failure_for_controlled_error(
            self, get_config, print_):
        get_config.side_effect = exceptions.ConfigurationError('invalid')

        with self.assertRaises(SystemExit) as error:
            shell.main()

        self.assertEqual(ExitCode.HANDLED_FAILURE, error.exception.code)
        print_.assert_called_once_with(
            json.dumps({
                'error': 'invalid',
            }),
            file=shell.sys.stderr,
        )

    @mock.patch.object(shell.sys, 'argv', [
        'vaultlocker', 'encrypt', '/dev/sdb',
    ])
    @mock.patch('builtins.print')
    @mock.patch.object(shell, 'get_config')
    def test_main_returns_unexpected_failure_for_unknown_error(
            self, get_config, print_):
        get_config.side_effect = RuntimeError('unexpected')

        with self.assertRaises(SystemExit) as error:
            shell.main()

        self.assertEqual(ExitCode.UNEXPECTED_FAILURE, error.exception.code)
        print_.assert_called_once_with(
            json.dumps({
                'error': 'unexpected',
            }),
            file=shell.sys.stderr,
        )

    @mock.patch.object(shell, '_vault_client')
    def test_retry_wrapper_returns_operation_result(self, vault_client):
        operation = mock.Mock(return_value={'luks_uuid': 'test-uuid'})
        args = mock.Mock(retry=-1)
        config = mock.Mock()

        result = shell._do_it_with_persistence(operation, args, config)

        self.assertEqual({'luks_uuid': 'test-uuid'}, result)
        operation.assert_called_once_with(
            args, vault_client.return_value, config,
        )

    @mock.patch.object(shell, '_vault_client')
    def test_retry_wrapper_reports_vault_errors(self, vault_client):
        vault_client.side_effect = hvac.exceptions.Forbidden('denied')

        with self.assertRaises(exceptions.VaultConnectionError):
            shell._do_it_with_persistence(
                mock.Mock(), mock.Mock(retry=-1), mock.Mock(),
            )
