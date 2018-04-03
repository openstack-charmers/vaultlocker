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


def _run_command(command, command_input):
    """Run a command and pipe data to it

    Runs the command as provided, writing the provided input
    to it.

    :param: command: subprocess compatible array to execute
    :param: command_input: string to write to command stdin
    :raises: CalledProcessError: in the event of a non-zero exit code.
    """
    logger.debug('Running command: {}'.format(' '.join(command)))
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE
    )
    _, stderr = process.communicate(command_input.encode('UTF-8'))
    returncode = process.wait()
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode,
                                            ' '.join(command),
                                            stderr)

def luks_format(key, device, uuid):
    """LUKS format a block device

    Format a block devices using dm-crypt/LUKS with the
    provided key and uuid

    :param: key: string containing the encryption key to use.
    :param: device: full path to block device to use.
    :param: uuid: uuid to use for encrypted block device.
    """
    logger.info('LUKS formatting {}/{}'.format(device, uuid))
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
    _run_command(command, key)


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
        'luksOpen',
        'UUID={}'.format(uuid),
        handle,
    ]
    _run_command(command, key)
    return handle
