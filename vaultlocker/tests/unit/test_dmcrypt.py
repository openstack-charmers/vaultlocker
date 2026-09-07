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
test_dmcrypt
----------------------------------

Tests for `dmcrypt` module.
"""

import base64
import subprocess
from unittest import mock

from vaultlocker import dmcrypt
from vaultlocker.tests.unit import base


class TestDMCrypt(base.TestCase):

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_format(self, _subprocess):
        dmcrypt.luks_format('mykey', '/dev/sdb', 'test-uuid')
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--uuid', 'test-uuid',
             '--key-file', '-',
             'luksFormat', '/dev/sdb'],
            input='mykey'.encode('UTF-8')
        )

    def test_key_bytes_from_string(self):
        self.assertEqual(
            dmcrypt._key_bytes("pässphrase"),
            "pässphrase".encode("utf-8"),
        )

    def test_key_bytes_from_bytes(self):
        key = b"passphrase"
        self.assertEqual(dmcrypt._key_bytes(key), key)

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_open(self, _subprocess):
        dmcrypt.luks_open('mykey', 'test-uuid')
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open', 'UUID=test-uuid', 'crypt-test-uuid',
             '--type', 'luks'],
            input='mykey'.encode('UTF-8')
        )

    @mock.patch.object(dmcrypt, 'os')
    def test_generate_key(self, _os):
        _key = b'randomdatastringfromentropy'
        _os.urandom.return_value = _key
        self.assertEqual(dmcrypt.generate_key(),
                         base64.b64encode(_key).decode('UTF-8'))
        _os.urandom.assert_called_with(dmcrypt.KEY_SIZE / 8)

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_uuid(self, _subprocess):
        _subprocess.check_output.return_value = b'test-uuid\n'

        self.assertEqual(
            dmcrypt.luks_uuid('/dev/sdb'),
            'test-uuid'
        )
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             'luksUUID',
             '/dev/sdb']
        )

    @mock.patch.object(dmcrypt.subprocess, 'check_output')
    def test_luks_uuid_failure(self, _check_output):
        _check_output.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=['cryptsetup']
        )

        with self.assertRaises(subprocess.CalledProcessError):
            dmcrypt.luks_uuid('/dev/sdb')

        _check_output.assert_called_once_with(
            ['cryptsetup',
             'luksUUID',
             '/dev/sdb']
        )

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_test_key_valid(self, _subprocess):
        self.assertTrue(
            dmcrypt.luks_test_key('mykey', '/dev/sdb')
        )
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open',
             '--test-passphrase',
             '/dev/sdb'],
            input=b'mykey'
        )

    @mock.patch.object(dmcrypt.subprocess, 'check_output')
    def test_luks_test_key_invalid(self, _check_output):
        _check_output.side_effect = subprocess.CalledProcessError(
            returncode=2,
            cmd=['cryptsetup']
        )

        self.assertFalse(
            dmcrypt.luks_test_key('mykey', '/dev/sdb')
        )
        _check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open',
             '--test-passphrase',
             '/dev/sdb'],
            input=b'mykey'
        )

    @mock.patch.object(dmcrypt.subprocess, 'check_output')
    def test_luks_test_key_command_failure(self, _check_output):
        _check_output.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=['cryptsetup']
        )

        with self.assertRaises(subprocess.CalledProcessError):
            dmcrypt.luks_test_key('mykey', '/dev/sdb')

        _check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open',
             '--test-passphrase',
             '/dev/sdb'],
            input=b'mykey'
        )

    @mock.patch.object(dmcrypt, 'subprocess')
    @mock.patch.object(dmcrypt, 'os')
    def test_luks_add_key(self, _os, _subprocess):
        _os.memfd_create.return_value = 10

        dmcrypt.luks_add_key(
            b'existing-key',
            'new-key',
            '/dev/sdb'
        )

        _os.memfd_create.assert_called_once_with(
            'vaultlocker-existing-key'
        )
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '/proc/self/fd/10',
             '--new-keyfile', '-',
             'luksAddKey', '/dev/sdb'],
            input=b'new-key',
            pass_fds=(10,)
        )
        _os.close.assert_called_once_with(10)

    @mock.patch.object(dmcrypt, 'subprocess')
    @mock.patch.object(dmcrypt, 'os')
    def test_luks_add_key_failure_closes_fd(
            self, _os, _subprocess):
        _os.memfd_create.return_value = 10
        _subprocess.check_output.side_effect = (
            subprocess.CalledProcessError(
                returncode=1,
                cmd=['cryptsetup']
            )
        )

        with self.assertRaises(subprocess.CalledProcessError):
            dmcrypt.luks_add_key(
                'existing-key',
                'new-key',
                '/dev/sdb'
            )
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '/proc/self/fd/10',
             '--new-keyfile', '-',
             'luksAddKey', '/dev/sdb'],
            input=b'new-key',
            pass_fds=(10,)
        )
        _os.close.assert_called_once_with(10)

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_udevadm_rescan(self, _subprocess):
        dmcrypt.udevadm_rescan('/dev/vdb')
        _subprocess.check_output.assert_called_once_with(
            ['udevadm',
             'trigger',
             '--name-match=/dev/vdb',
             '--action=add']
        )

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_udevadm_settle(self, _subprocess):
        dmcrypt.udevadm_settle('myuuid')
        _subprocess.check_output.assert_called_once_with(
            ['udevadm',
             'settle',
             '--exit-if-exists=/dev/disk/by-uuid/myuuid']
        )
