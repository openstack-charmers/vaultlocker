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
    subprocess.check_output(command,
                            input=key.encode('UTF-8'))


def luks_open(key, uuid):
    """LUKS open a block device by UUID

    Open a block device using dm-crypt/LUKS with the
    provided key and uuid

    :param: key: string containing the encryption key to use.
    :param: uuid: uuid to use for encrypted block device.
    :returns: str. dm-crypt mapping
    """
    logger.info('LUKS opening {}'.format(uuid))
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
    subprocess.check_output(command,
                            input=key.encode('UTF-8'))
    return handle


def udevadm_rescan(device):
    """udevadm trigger for block device addition

    Rescan for block devices to ensure that by-uuid devices are
    created before use.

    :param: device: full path to block device to use.
    """
    logger.info('udevadm trigger block/add for {}'.format(device))
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
    logger.info('udevadm settle /dev/disk/by-uuid/{}'.format(uuid))
    command = [
        'udevadm',
        'settle',
        '--exit-if-exists=/dev/disk/by-uuid/{}'.format(uuid),
    ]
    subprocess.check_output(command)
