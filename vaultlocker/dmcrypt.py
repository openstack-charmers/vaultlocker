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

import base64
import logging
import os
import subprocess

logger = logging.getLogger(__name__)


KEY_SIZE = 4096


def _key_bytes(key):
    """Normalize key material for subprocess input.

    Vault-managed keys are stored as strings, operator-provided keys
    read from stdin or a file are already bytes.
    """
    if isinstance(key, bytes):
        return key
    return key.encode('utf-8')


def generate_key():
    """Generate a 4096 bit random key for use with dm-crypt

    :returns: str.  Base64 encoded 4096 bit key
    """
    data = os.urandom(int(KEY_SIZE / 8))
    key = base64.b64encode(data).decode('utf-8')
    return key


def luks_format(key, device, uuid):
    """LUKS format a block device

    Format a block device using dm-crypt/LUKS with the
    provided key and uuid

    :param: key: string containing the encryption key to use.
    :param: device: full path to block device to use.
    :param: uuid: uuid to use for encrypted block device.
    """
    logger.info('LUKS formatting {} using UUID:{}'.format(device, uuid))
    command = [
        'cryptsetup',
        '--batch-mode',
        '--uuid',
        uuid,
        '--key-file',
        '-',
        'luksFormat',
        device,
    ]
    subprocess.check_output(
        command,
        input=_key_bytes(key),
    )


def luks_open(key, uuid):
    """LUKS open a block device by UUID.

    Open a block device using dm-crypt/LUKS with the
    provided key and uuid

    :param: key: string containing the encryption key to use.
    :param: uuid: uuid to use for encrypted block device.
    :returns: str. dm-crypt mapping
    """
    logger.info('LUKS opening %s', uuid)
    handle = 'crypt-{}'.format(uuid)
    command = [
        'cryptsetup',
        '--batch-mode',
        '--key-file',
        '-',
        'open',
        'UUID={}'.format(uuid),
        handle,
        '--type',
        'luks',
    ]
    subprocess.check_output(
        command,
        input=_key_bytes(key),
    )
    return handle


def luks_uuid(device):
    """Get the UUID of a LUKS-formatted block device.

    :param: device: full path to block device to use.
    :returns: str. UUID of the LUKS-formatted block device.
    """
    logger.info('Getting LUKS UUID for %s', device)
    command = [
        'cryptsetup',
        'luksUUID',
        device,
    ]
    return subprocess.check_output(command).decode('utf-8').strip()


def luks_test_key(key, device):
    """Test a key against a LUKS-formatted block device.

    :param: key: encryption key to test.
    :param: device: full path to block device to use.
    :returns: bool. True if the key is valid, otherwise False.
    """
    logger.info('Testing LUKS key for %s', device)
    # `--key-file -` for cryptsetup to read the passphrase from stdin
    command = [
        'cryptsetup',
        '--batch-mode',
        '--key-file',
        '-',
        'open',
        '--test-passphrase',
        device,
    ]

    try:
        subprocess.check_output(
            command,
            input=_key_bytes(key),
        )
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 2:
            return False
        raise

    return True


def luks_add_key(existing_key, new_key, device):
    """Add a key to a LUKS-formatted block device.

    :param: existing_key: existing valid encryption key.
    :param: new_key: new encryption key to add.
    :param: device: full path to block device to use.
    """
    logger.info('Adding a new LUKS key to %s', device)

    existing_key_fd = os.memfd_create(
        'vaultlocker-existing-key'
    )
    try:
        os.write(
            existing_key_fd,
            _key_bytes(existing_key),
        )
        os.lseek(existing_key_fd, 0, os.SEEK_SET)

        command = [
            'cryptsetup',
            '--batch-mode',
            '--key-file',
            '/proc/self/fd/{}'.format(existing_key_fd),  # existing via memfd
            '--new-keyfile',  # new key via stdin
            '-',
            'luksAddKey',
            device,
        ]
        subprocess.check_output(
            command,
            input=_key_bytes(new_key),
            pass_fds=(existing_key_fd,),
        )
    finally:
        os.close(existing_key_fd)


def udevadm_rescan(device):
    """udevadm trigger for block device addition.

    Rescan for block devices to ensure that by-uuid devices are
    created before use.

    :param: device: full path to block device to use.
    """
    logger.info('udevadm trigger block/add for %s', device)
    command = [
        'udevadm',
        'trigger',
        '--name-match={}'.format(device),
        '--action=add'
    ]
    subprocess.check_output(command)


def udevadm_settle(uuid):
    """udevadm settle the newly created encrypted device

    Ensure udev has created the by-uuid symlink for newly
    created encyprted device.

    :param: uuid: uuid to use for encrypted block device.
    """
    logger.info('udevadm settle /dev/disk/by-uuid/%s', uuid)
    command = [
        'udevadm',
        'settle',
        '--exit-if-exists=/dev/disk/by-uuid/{}'.format(uuid),
    ]
    subprocess.check_output(command)
