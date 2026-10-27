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
import re
import stat
import subprocess

logger = logging.getLogger(__name__)


KEY_SIZE = 4096

#: Maximum time to wait for a cryptsetup command.
CRYPTSETUP_TIMEOUT_SECONDS = 300

#: Maximum time to wait for a udevadm command.
UDEVADM_TIMEOUT_SECONDS = 60

#: cryptsetup options bypassing the dm-crypt read and write workqueues.
NO_WORKQUEUE_OPTIONS = (
    '--perf-no_read_workqueue',
    '--perf-no_write_workqueue',
)

#: First kernel release whose dm-crypt target can bypass its workqueues.
NO_WORKQUEUE_MIN_KERNEL = (5, 9, 0)

#: First cryptsetup release providing the workqueue bypass options.
NO_WORKQUEUE_MIN_CRYPTSETUP = (2, 3, 4)

#: sysfs directory linking block device numbers to their devices.
SYSFS_DEV_BLOCK = '/sys/dev/block'


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
        timeout=CRYPTSETUP_TIMEOUT_SECONDS,
    )


def _version(text):
    """Parse the first dotted version number in a string.

    :param: text: string containing a version, e.g. a kernel release.
    :returns: tuple. Major, minor and patch numbers.
    :raises ValueError: if the string contains no version.
    """
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', text)
    if not match:
        raise ValueError('Unable to parse a version from {!r}'.format(text))
    return tuple(int(part) for part in match.groups(default='0'))


def cryptsetup_version():
    """Get the installed cryptsetup version.

    :returns: tuple. Major, minor and patch numbers.
    """
    output = subprocess.check_output(
        ['cryptsetup', '--version'],
        timeout=CRYPTSETUP_TIMEOUT_SECONDS,
    ).decode('utf-8')
    return _version(output)


def _sysfs_block_dir(device):
    """Return the sysfs directory of a block device node.

    :param: device: path to a block device node or a symlink to one.
    :returns: str. Resolved sysfs directory of the device.
    :raises ValueError: if the path is not a block device.
    """
    device_stat = os.stat(device)
    if not stat.S_ISBLK(device_stat.st_mode):
        raise ValueError('{} is not a block device'.format(device))
    return os.path.realpath(os.path.join(
        SYSFS_DEV_BLOCK,
        '{}:{}'.format(
            os.major(device_stat.st_rdev),
            os.minor(device_stat.st_rdev),
        ),
    ))


def _sysfs_rotational(sysfs_dir):
    """Return whether any storage beneath a sysfs block device rotates.

    Partitions are resolved through their parent disk, and stacked
    devices such as LVM, multipath and MD RAID through their slaves.

    :param: sysfs_dir: resolved sysfs directory of a block device.
    :returns: bool. True if any backing device is rotational.
    """
    if os.path.exists(os.path.join(sysfs_dir, 'partition')):
        # The parent may itself be a stacked device, e.g. an MD array.
        return _sysfs_rotational(os.path.dirname(sysfs_dir))

    slaves_dir = os.path.join(sysfs_dir, 'slaves')
    slaves = os.listdir(slaves_dir) if os.path.isdir(slaves_dir) else []
    if slaves:
        return any(
            _sysfs_rotational(
                os.path.realpath(os.path.join(slaves_dir, slave))
            )
            for slave in slaves
        )

    with open(os.path.join(sysfs_dir, 'queue', 'rotational')) as rotational:
        return rotational.read().strip() != '0'


def is_rotational(device):
    """Determine whether a block device is backed by rotational storage.

    :param: device: path to a block device node or a symlink to one.
    :returns: bool. True if any backing device is rotational.
    """
    return _sysfs_rotational(_sysfs_block_dir(device))


def can_bypass_workqueues(device):
    """Determine whether to bypass the dm-crypt workqueues for a device.

    The workqueues are bypassed when the kernel and cryptsetup support
    it and all storage backing the device is non-rotational. If any of
    these cannot be determined, the workqueues are kept.

    :param: device: path to the LUKS block device.
    :returns: bool. True if the workqueues can be bypassed.
    """
    try:
        kernel = os.uname().release
        if _version(kernel) < NO_WORKQUEUE_MIN_KERNEL:
            logger.info(
                'Keeping dm-crypt workqueues for %s: kernel %s does not '
                'support bypassing them', device, kernel,
            )
            return False

        if is_rotational(device):
            logger.info(
                'Keeping dm-crypt workqueues for %s: backing storage is '
                'rotational', device,
            )
            return False

        if cryptsetup_version() < NO_WORKQUEUE_MIN_CRYPTSETUP:
            logger.info(
                'Keeping dm-crypt workqueues for %s: cryptsetup is older '
                'than %s', device,
                '.'.join(str(part) for part in NO_WORKQUEUE_MIN_CRYPTSETUP),
            )
            return False
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        logger.warning(
            'Keeping dm-crypt workqueues for %s: unable to determine '
            'support for bypassing them: %s', device, error,
        )
        return False

    return True


def luks_open(key, uuid, device=None, bypass_workqueues=False):
    """LUKS open a block device.

    Open a block device using dm-crypt/LUKS with the
    provided key and device path or UUID.

    :param: key: string containing the encryption key to use.
    :param: uuid: uuid to use for encrypted block device.
    :param: device: optional block device path. If omitted, use the UUID.
    :param: bypass_workqueues: bypass the dm-crypt workqueues when the
        kernel, cryptsetup and backing storage support it.
    :returns: str. dm-crypt mapping
    """
    logger.info('LUKS opening %s', uuid)
    handle = 'crypt-{}'.format(uuid)
    source = device if device else 'UUID={}'.format(uuid)
    command = [
        'cryptsetup',
        '--batch-mode',
        '--key-file',
        '-',
        'open',
        source,
        handle,
        '--type',
        'luks',
    ]
    if bypass_workqueues and can_bypass_workqueues(
            device or '/dev/disk/by-uuid/{}'.format(uuid)):
        logger.info('Bypassing dm-crypt workqueues for %s', handle)
        command.extend(NO_WORKQUEUE_OPTIONS)
    subprocess.check_output(
        command,
        input=_key_bytes(key),
        timeout=CRYPTSETUP_TIMEOUT_SECONDS,
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
    return subprocess.check_output(
        command,
        timeout=CRYPTSETUP_TIMEOUT_SECONDS,
    ).decode('utf-8').strip()


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
            timeout=CRYPTSETUP_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as exc:
        # cryptsetup returns exit code 2 for incorrect passphrase
        # with --test-passphrase, this confirms that the given key
        # does not unlock the device. Other exit codes are inconclusive
        # and should be raised.
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
            timeout=CRYPTSETUP_TIMEOUT_SECONDS,
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
    subprocess.check_output(
        command,
        timeout=UDEVADM_TIMEOUT_SECONDS,
    )


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
    subprocess.check_output(
        command,
        timeout=UDEVADM_TIMEOUT_SECONDS,
    )
