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
import os
import stat
import subprocess
import tempfile
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
            input='mykey'.encode('UTF-8'),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
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
            input='mykey'.encode('UTF-8'),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_open_by_device(self, _subprocess):
        dmcrypt.luks_open('mykey', 'test-uuid', '/dev/sdb')
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open', '/dev/sdb', 'crypt-test-uuid',
             '--type', 'luks'],
            input='mykey'.encode('UTF-8'),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt, 'can_bypass_workqueues', return_value=True)
    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_open_bypasses_workqueues(self, _subprocess, _can_bypass):
        dmcrypt.luks_open('mykey', 'test-uuid', bypass_workqueues=True)
        _can_bypass.assert_called_once_with('/dev/disk/by-uuid/test-uuid')
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open', 'UUID=test-uuid', 'crypt-test-uuid',
             '--type', 'luks',
             '--perf-no_read_workqueue',
             '--perf-no_write_workqueue'],
            input='mykey'.encode('UTF-8'),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt, 'can_bypass_workqueues', return_value=True)
    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_open_by_device_bypasses_workqueues(
            self, _subprocess, _can_bypass):
        dmcrypt.luks_open(
            'mykey', 'test-uuid', '/dev/sdb', bypass_workqueues=True,
        )
        _can_bypass.assert_called_once_with('/dev/sdb')
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open', '/dev/sdb', 'crypt-test-uuid',
             '--type', 'luks',
             '--perf-no_read_workqueue',
             '--perf-no_write_workqueue'],
            input='mykey'.encode('UTF-8'),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt, 'can_bypass_workqueues', return_value=False)
    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_open_keeps_workqueues_when_unsupported(
            self, _subprocess, _can_bypass):
        dmcrypt.luks_open(
            'mykey', 'test-uuid', '/dev/sdb', bypass_workqueues=True,
        )
        _can_bypass.assert_called_once_with('/dev/sdb')
        _subprocess.check_output.assert_called_once_with(
            ['cryptsetup',
             '--batch-mode',
             '--key-file', '-',
             'open', '/dev/sdb', 'crypt-test-uuid',
             '--type', 'luks'],
            input='mykey'.encode('UTF-8'),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt, 'can_bypass_workqueues')
    @mock.patch.object(dmcrypt, 'subprocess')
    def test_luks_open_does_not_probe_when_disabled(
            self, _subprocess, _can_bypass):
        dmcrypt.luks_open('mykey', 'test-uuid', '/dev/sdb')
        _can_bypass.assert_not_called()

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
             '/dev/sdb'],
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
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
             '/dev/sdb'],
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
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
            input=b'mykey',
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
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
            input=b'mykey',
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
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
            input=b'mykey',
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
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
            pass_fds=(10,),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
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
            pass_fds=(10,),
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
        )
        _os.close.assert_called_once_with(10)

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_udevadm_rescan(self, _subprocess):
        dmcrypt.udevadm_rescan('/dev/vdb')
        _subprocess.check_output.assert_called_once_with(
            ['udevadm',
             'trigger',
             '--name-match=/dev/vdb',
             '--action=add'],
            timeout=dmcrypt.UDEVADM_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt, 'subprocess')
    def test_udevadm_settle(self, _subprocess):
        dmcrypt.udevadm_settle('myuuid')
        _subprocess.check_output.assert_called_once_with(
            ['udevadm',
             'settle',
             '--exit-if-exists=/dev/disk/by-uuid/myuuid'],
            timeout=dmcrypt.UDEVADM_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt.subprocess, 'check_output')
    def test_luks_format_timeout_propagates(self, _check_output):
        _check_output.side_effect = subprocess.TimeoutExpired(
            cmd='cryptsetup', timeout=1,
        )

        with self.assertRaises(subprocess.TimeoutExpired):
            dmcrypt.luks_format('mykey', '/dev/sdb', 'test-uuid')


class TestWorkqueueBypass(base.TestCase):
    """Tests deciding whether to bypass the dm-crypt workqueues."""

    def test_version_parses_kernel_release(self):
        self.assertEqual((7, 0, 0), dmcrypt._version('7.0.0-38-generic'))
        self.assertEqual((5, 9, 0), dmcrypt._version('5.9-rc1'))

    def test_version_parses_cryptsetup_output(self):
        self.assertEqual(
            (2, 7, 0),
            dmcrypt._version('cryptsetup 2.7.0 flags: UDEV BLKID KEYRING\n'),
        )

    def test_version_rejects_text_without_version(self):
        with self.assertRaises(ValueError):
            dmcrypt._version('cryptsetup')

    @mock.patch.object(dmcrypt.subprocess, 'check_output')
    def test_cryptsetup_version(self, _check_output):
        _check_output.return_value = b'cryptsetup 2.3.7\n'

        self.assertEqual((2, 3, 7), dmcrypt.cryptsetup_version())
        _check_output.assert_called_once_with(
            ['cryptsetup', '--version'],
            timeout=dmcrypt.CRYPTSETUP_TIMEOUT_SECONDS,
        )

    @mock.patch.object(dmcrypt, 'cryptsetup_version', return_value=(2, 7, 0))
    @mock.patch.object(dmcrypt, 'is_rotational', return_value=False)
    @mock.patch.object(dmcrypt.os, 'uname')
    def test_bypass_when_supported_and_non_rotational(
            self, _uname, _is_rotational, _cryptsetup_version):
        _uname.return_value.release = '7.0.0-38-generic'

        self.assertTrue(dmcrypt.can_bypass_workqueues('/dev/nvme0n1'))
        _is_rotational.assert_called_once_with('/dev/nvme0n1')

    @mock.patch.object(dmcrypt, 'cryptsetup_version')
    @mock.patch.object(dmcrypt, 'is_rotational')
    @mock.patch.object(dmcrypt.os, 'uname')
    def test_keep_workqueues_on_old_kernel(
            self, _uname, _is_rotational, _cryptsetup_version):
        _uname.return_value.release = '5.8.0-63-generic'

        self.assertFalse(dmcrypt.can_bypass_workqueues('/dev/nvme0n1'))
        _is_rotational.assert_not_called()
        _cryptsetup_version.assert_not_called()

    @mock.patch.object(dmcrypt, 'cryptsetup_version')
    @mock.patch.object(dmcrypt, 'is_rotational', return_value=True)
    @mock.patch.object(dmcrypt.os, 'uname')
    def test_keep_workqueues_on_rotational_storage(
            self, _uname, _is_rotational, _cryptsetup_version):
        _uname.return_value.release = '6.8.0-31-generic'

        self.assertFalse(dmcrypt.can_bypass_workqueues('/dev/sdb'))
        _cryptsetup_version.assert_not_called()

    @mock.patch.object(dmcrypt, 'cryptsetup_version', return_value=(2, 3, 3))
    @mock.patch.object(dmcrypt, 'is_rotational', return_value=False)
    @mock.patch.object(dmcrypt.os, 'uname')
    def test_keep_workqueues_with_old_cryptsetup(
            self, _uname, _is_rotational, _cryptsetup_version):
        _uname.return_value.release = '6.8.0-31-generic'

        self.assertFalse(dmcrypt.can_bypass_workqueues('/dev/nvme0n1'))

    @mock.patch.object(dmcrypt, 'cryptsetup_version', return_value=(2, 7, 0))
    @mock.patch.object(dmcrypt, 'is_rotational', return_value=False)
    @mock.patch.object(dmcrypt.os, 'uname')
    def test_keep_workqueues_when_detection_fails(
            self, _uname, _is_rotational, _cryptsetup_version):
        _uname.return_value.release = '6.8.0-31-generic'
        failures = (
            ('is_rotational', FileNotFoundError('no such device')),
            ('is_rotational', ValueError('not a block device')),
            ('cryptsetup_version', subprocess.CalledProcessError(
                returncode=1, cmd='cryptsetup --version')),
            ('cryptsetup_version', subprocess.TimeoutExpired(
                cmd='cryptsetup --version', timeout=300)),
        )
        for name, failure in failures:
            with self.subTest(name=name, failure=failure):
                with mock.patch.object(dmcrypt, name, side_effect=failure):
                    self.assertFalse(
                        dmcrypt.can_bypass_workqueues('/dev/nvme0n1'),
                    )

    @mock.patch.object(dmcrypt, 'is_rotational')
    @mock.patch.object(dmcrypt.os, 'uname')
    def test_keep_workqueues_with_unknown_kernel(
            self, _uname, _is_rotational):
        _uname.return_value.release = 'unknown'

        self.assertFalse(dmcrypt.can_bypass_workqueues('/dev/nvme0n1'))
        _is_rotational.assert_not_called()


class TestRotational(base.TestCase):
    """Tests resolving rotational storage through sysfs."""

    def setUp(self):
        super().setUp()
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.sysfs = temp_dir.name

        # Non-rotational disk with a partition.
        self.nvme = self._disk('devices/nvme0n1', rotational='0')
        self.nvme_part = self._partition(self.nvme, 'nvme0n1p1')
        # Rotational disk.
        self.sda = self._disk('devices/sda', rotational='1')
        # LVM on the NVMe partition. Some kernels report device-mapper
        # devices as rotational, so the slaves decide.
        self.lv = self._disk(
            'devices/virtual/dm-0', rotational='1',
            slaves=[self.nvme_part],
        )
        # LVM spanning both disks.
        self.mixed_lv = self._disk(
            'devices/virtual/dm-1', rotational='0',
            slaves=[self.nvme_part, self.sda],
        )
        # A device stacked on the first LVM volume.
        self.nested = self._disk(
            'devices/virtual/dm-2', rotational='1', slaves=[self.lv],
        )
        # A partitioned MD array on the NVMe disk. Linux reports a
        # degraded array as rotational, so the slaves decide.
        self.md = self._disk(
            'devices/virtual/md0', rotational='1', slaves=[self.nvme],
        )
        self.md_part = self._partition(self.md, 'md0p1')

    def _disk(self, path, rotational, slaves=()):
        disk = os.path.join(self.sysfs, path)
        os.makedirs(os.path.join(disk, 'queue'))
        os.makedirs(os.path.join(disk, 'slaves'))
        with open(os.path.join(disk, 'queue', 'rotational'), 'w') as f:
            f.write('{}\n'.format(rotational))
        for slave in slaves:
            os.symlink(
                slave,
                os.path.join(disk, 'slaves', os.path.basename(slave)),
            )
        return disk

    def _partition(self, disk, name):
        partition = os.path.join(disk, name)
        os.makedirs(partition)
        with open(os.path.join(partition, 'partition'), 'w') as f:
            f.write('1\n')
        return partition

    def test_non_rotational_disk(self):
        self.assertFalse(dmcrypt._sysfs_rotational(self.nvme))

    def test_partition_uses_parent_disk(self):
        self.assertFalse(dmcrypt._sysfs_rotational(self.nvme_part))

    def test_rotational_disk(self):
        self.assertTrue(dmcrypt._sysfs_rotational(self.sda))

    def test_device_mapper_resolves_slaves(self):
        self.assertFalse(dmcrypt._sysfs_rotational(self.lv))

    def test_any_rotational_slave_is_rotational(self):
        self.assertTrue(dmcrypt._sysfs_rotational(self.mixed_lv))

    def test_nested_device_mapper_resolves_slaves(self):
        self.assertFalse(dmcrypt._sysfs_rotational(self.nested))

    def test_partition_of_stacked_device_resolves_slaves(self):
        self.assertFalse(dmcrypt._sysfs_rotational(self.md))
        self.assertFalse(dmcrypt._sysfs_rotational(self.md_part))

    def test_missing_rotational_attribute_raises(self):
        os.remove(os.path.join(self.nvme, 'queue', 'rotational'))

        with self.assertRaises(OSError):
            dmcrypt._sysfs_rotational(self.nvme_part)

    def test_is_rotational_resolves_device_number(self):
        dev_block = os.path.join(self.sysfs, 'dev', 'block')
        os.makedirs(dev_block)
        os.symlink(self.lv, os.path.join(dev_block, '252:0'))
        real_stat = os.stat

        def fake_stat(path, *args, **kwargs):
            if path == '/dev/vg/lv':
                return mock.Mock(
                    st_mode=stat.S_IFBLK | 0o660,
                    st_rdev=os.makedev(252, 0),
                )
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(dmcrypt, 'SYSFS_DEV_BLOCK', dev_block), \
                mock.patch.object(dmcrypt.os, 'stat', side_effect=fake_stat):
            self.assertFalse(dmcrypt.is_rotational('/dev/vg/lv'))

    def test_is_rotational_rejects_non_block_device(self):
        regular_file = os.path.join(self.sysfs, 'regular')
        open(regular_file, 'w').close()

        with self.assertRaises(ValueError):
            dmcrypt.is_rotational(regular_file)
