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

"""Select the boot-time unlock backend for the running distribution.

The classic (deb/pip) deployment uses a systemd template unit plus a
per-device configuration drop-in. The snap deployment uses Pebble
layers because a strictly confined snap cannot manipulate host systemd
units at runtime.
"""

import logging
import os

from vaultlocker import pebble_layers
from vaultlocker import systemd

logger = logging.getLogger(__name__)

#: Environment variable snapd sets when a process runs inside a snap.
SNAP_ENV_VAR = 'SNAP'

#: Default number of seconds to retry Vault at boot before giving up
#: for this attempt (the unlock service is retried again afterwards).
DEFAULT_RETRY_TIMEOUT_SECONDS = 10000


def running_in_snap():
    """Return True when running inside a snap environment.

    :returns: bool.
    """
    return bool(os.environ.get(SNAP_ENV_VAR))


def register(block_uuid, config_path,
             timeout=DEFAULT_RETRY_TIMEOUT_SECONDS):
    """Register boot-time unlock for a managed device.

    Chooses the Pebble backend inside a snap and the systemd backend
    otherwise.

    :param: block_uuid: UUID of the encrypted block device.
    :param: config_path: Path to the vaultlocker configuration file.
    :param: timeout: Seconds to retry connecting to Vault at boot.
    """
    if running_in_snap():
        logger.info('Registering snap (Pebble) boot unlock for %s',
                    block_uuid)
        pebble_layers.register_boot_unlock(
            block_uuid, config_path, timeout,
        )
    else:
        logger.info('Registering systemd boot unlock for %s', block_uuid)
        systemd.register_decrypt_service(block_uuid, config_path)
