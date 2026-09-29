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

import logging
import os
import subprocess

logger = logging.getLogger(__name__)


#: Directory systemd reads unit files and drop-ins from.
SYSTEMD_UNIT_DIR = '/etc/systemd/system'

#: Template for the per-device boot-time unlock unit.
DECRYPT_SERVICE_TEMPLATE = 'vaultlocker-decrypt@{}.service'

#: Name of the drop-in file written per managed device.
CONFIG_DROPIN_NAME = 'config.conf'


def enable(service_name):
    """Enable a systemd unit

    :param: service_name: Name of the service to enable.
    """
    logging.info('Enabling systemd unit for {}'.format(service_name))
    cmd = ['systemctl', 'enable', service_name]
    subprocess.check_call(cmd)


def config_dropin_path(service_name):
    """Return the config drop-in path for a per-device unlock unit.

    :param: service_name: Name of the templated unit instance.
    :returns: str. Full path to the drop-in override file.
    """
    return os.path.join(
        SYSTEMD_UNIT_DIR,
        '{}.d'.format(service_name),
        CONFIG_DROPIN_NAME,
    )


def write_config_dropin(service_name, config_path):
    """Write a drop-in pinning a unit instance to a vaultlocker config.

    Per-application vaultlocker instances keep their own configuration
    file, so the boot-time unlock unit for a device must use the same
    configuration file that managed the device.

    :param: service_name: Name of the templated unit instance.
    :param: config_path: Path to the vaultlocker configuration file.
    """
    dropin_path = config_dropin_path(service_name)
    os.makedirs(os.path.dirname(dropin_path), exist_ok=True)
    logging.info('Writing config drop-in %s', dropin_path)
    with open(dropin_path, 'w') as dropin:
        dropin.write(
            '[Service]\n'
            'Environment=VAULTLOCKER_CONFIG={}\n'.format(config_path)
        )


def register_decrypt_service(block_uuid, config_path):
    """Configure and enable boot-time unlock for a managed device.

    Writes the per-device configuration drop-in and enables the
    templated decrypt unit.

    :param: block_uuid: UUID of the encrypted block device.
    :param: config_path: Path to the vaultlocker configuration file.
    """
    service_name = DECRYPT_SERVICE_TEMPLATE.format(block_uuid)
    write_config_dropin(service_name, config_path)
    enable(service_name)
