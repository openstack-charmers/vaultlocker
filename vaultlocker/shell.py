
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

import argparse
import configparser
import logging
import pathlib
import platform
import socket
import subprocess
import uuid

import hvac
import tenacity

from vaultlocker import dmcrypt, exceptions, systemd, vault

logger = logging.getLogger(__name__)

DEFAULT_CONF_FILE = '/etc/vaultlocker/vaultlocker.conf'


def _vault_client(config):
    """Helper wrapper to create Vault Client

    :param: config: configparser object of vaultlocker config
    :returns: hvac.Client. configured Vault Client object
    """
    client = hvac.Client(
        url=config.get('vault', 'url'),
        verify=config.get('vault', 'ca_bundle', fallback=True)
    )
    client.auth.approle.login(
        role_id=config.get('vault', 'approle'),
        secret_id=config.get('vault', 'secret_id')
    )
    return client


def _get_kv_version(config):
    """Return the configured Vault KV version.

    :param config: configparser object of vaultlocker config
    :returns: str: KV version ('1' or '2')
    :raises ValueError: If the configured value is not '1' or '2'.
    """
    version = config.get('vault', 'kv_version', fallback=vault.KV_VERSION_1)
    if version not in (vault.KV_VERSION_1, vault.KV_VERSION_2):
        raise ValueError(
            f"Invalid kv_version '{version}' in vaultlocker config; "
            f"must be '{vault.KV_VERSION_1}' or '{vault.KV_VERSION_2}'"
        )
    return version


def get_hostname(config):
    """Determine the hostname to use in Vault paths.

    :param config: configparser object of vaultlocker config
    :returns: str: hostname to use
    :raises RuntimeError: if no hostname could be determined
    """
    configured = config.get('DEFAULT', 'hostname', fallback=None)
    if configured:
        return configured

    node = platform.node()
    if node:
        return node

    try:
        return socket.gethostname()
    except OSError as hostname_error:
        raise RuntimeError(
            f'Unable to determine hostname: {hostname_error}'
        )


def _vault_mount_point(config):
    """Return the configured Vault secrets-engine mount.

    :param config: configparser object of vaultlocker config
    :returns: Vault secrets-engine mount point
    """
    return config.get('vault', 'backend')


def _vault_secret_path(device_uuid, config):
    """Return the secret path relative to the Vault mount.

    :param device_uuid: String of the device UUID
    :param config: configparser object of vaultlocker config
    :returns: Path ``<hostname>/<uuid>`` form
    """
    return f'{get_hostname(config)}/{device_uuid}'


def _get_vault_path(device_uuid, config):
    """Return the complete Vault path.

    :param device_uuid: String of the device UUID
    :param config: configparser object of vaultlocker config
    :returns: Path in ``<mount>/<hostname>/<uuid>`` form.
    """
    return f'{_vault_mount_point(config)}/{_vault_secret_path(device_uuid, config)}'


def _vault_store(client, config):
    """Create store for the configured Vault KV mount.

    :param client: Authenticated Vault client.
    :param config: Parsed vaultlocker configuration.
    :returns: Storage configured with the mount and KV version.
    """
    return vault.KVStore.get_store(
        client=client,
        mount_point=_vault_mount_point(config),
        kv_version=_get_kv_version(config),
    )


def _encrypt_block_device(args, client, config):
    """Encrypt and open a block device

    Stores the dm-crypt key direct in vault

    :param: args: argparser generated cli arguments
    :param: client: hvac.Client for Vault access
    :param: config: configparser object of vaultlocker config
    """
    block_device = args.block_device[0]
    key = dmcrypt.generate_key()
    block_uuid = str(uuid.uuid4()) if not args.uuid else args.uuid

    path = _vault_secret_path(block_uuid, config)
    vault_path = f'{_vault_mount_point(config)}/{path}'
    store = _vault_store(client, config)

    # NOTE: store and validate key before trying to encrypt disk
    try:
        store.write(
            path,
            {'dmcrypt_key': key},
        )
    except hvac.exceptions.VaultError as write_error:
        logger.error(
            'Vault write to path %s failed with error: %s',
            vault_path,
            write_error,
        )
        raise exceptions.VaultWriteError(
            vault_path,
            write_error,
        )

    try:
        stored_data = store.read(path)
    except hvac.exceptions.VaultError as read_error:
        logger.error(
            'Vault access to path %s failed with error: %s',
            vault_path,
            read_error,
        )
        raise exceptions.VaultReadError(
            vault_path,
            read_error,
        )

    if not key == stored_data['dmcrypt_key']:
        raise exceptions.VaultKeyMismatch(vault_path)

    # All function calls within try/catch raise a CalledProcessError
    # if return code is non-zero
    # This way if any of the calls fail, the key can be removed from vault
    try:
        dmcrypt.luks_format(key, block_device, block_uuid)
        # Ensure sym link for new encrypted device is created
        # LP Bug #1780332
        dmcrypt.udevadm_rescan(block_device)
        dmcrypt.udevadm_settle(block_uuid)
        dmcrypt.luks_open(key, block_uuid)
    except subprocess.CalledProcessError as luks_error:
        logger.error(
            'LUKS formatting %s failed with error code: %s\n'
            'LUKS output: %s',
            block_device,
            luks_error.returncode,
            luks_error.output,
        )

        try:
            store.delete(path)
        except hvac.exceptions.VaultError as del_error:
            raise exceptions.VaultDeleteError(vault_path, del_error)

        raise exceptions.LUKSFailure(block_device, luks_error.output)

    systemd.enable(f'vaultlocker-decrypt@{block_uuid}.service')


def _decrypt_block_device(args, client, config):
    """Open a LUKS/dm-crypt encrypted block device

    The device's dm-crypt key is retrieved from Vault

    :param: args: argparser generated cli arguments
    :param: client: hvac.Client for Vault access
    :param: config: configparser object of vaultlocker config
    """
    block_uuid = args.uuid[0]

    if _device_exists(block_uuid):
        logger.info(
            'Skipping setup of %s because it already exists.',
            block_uuid,
        )
        return

    path = _vault_secret_path(block_uuid, config)
    store = _vault_store(client, config)

    try:
        stored_data = store.read(path)
    except hvac.exceptions.InvalidPath:
        raise ValueError(
            f'Unable to locate key for {block_uuid}'
        )

    key = stored_data['dmcrypt_key']

    dmcrypt.luks_open(key, block_uuid)


def _device_exists(block_uuid):
    """Checks if the device already exists."""
    handle = f'crypt-{block_uuid}'
    path = f"/dev/mapper/{handle}"
    logger.info('Checking if %s exists.', path)
    return pathlib.Path(path).exists()


def _do_it_with_persistence(func, args, config):
    """Exec func with retries based on provided cli flags

    :param: func: function to attempt to execute
    :param: args: argparser generated cli arguments
    :param: config: configparser object of vaultlocker config
    """
    @tenacity.retry(
        wait=tenacity.wait_fixed(1),
        reraise=True,
        stop=(
            tenacity.stop_after_delay(args.retry) if args.retry > 0
            else tenacity.stop_after_attempt(1)
            ),
        retry=(
            tenacity.retry_if_exception(hvac.exceptions.VaultNotInitialized) |
            tenacity.retry_if_exception(hvac.exceptions.VaultDown)
            )
        )
    def _do_it():
        client = _vault_client(config)
        func(args, client, config)
    _do_it()


def encrypt(args, config):
    """Encrypt and open handler

    :param: args: argparser generated cli arguments
    :param: config: configparser object of vaultlocker config
    """
    _do_it_with_persistence(_encrypt_block_device, args, config)


def decrypt(args, config):
    """Decrypt and open handler

    :param: args: argparser generated cli arguments
    :param: config: configparser object of vaultlocker config
    """
    _do_it_with_persistence(_decrypt_block_device, args, config)


def get_config(config_path):
    """Read vaultlocker configuration from config file

    :param: config_path: path to the configuration file
    :returns: configparser. Parsed configuration options
    """
    config = configparser.ConfigParser()
    if pathlib.Path(config_path).exists():
        config.read(config_path)
    else:
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )
    return config


def main():
    parser = argparse.ArgumentParser('vaultlocker')
    parser.set_defaults(prog=parser.prog)
    subparsers = parser.add_subparsers(
        title="subcommands",
        description="valid subcommands",
        help="sub-command help",
    )
    parser.add_argument(
        '--retry',
        default=-1,
        type=int,
        help="Time in seconds to continue retrying to connect to Vault"
    )
    parser.add_argument(
        '--config',
        default=DEFAULT_CONF_FILE,
        type=str,
        help="Path to vaultlocker configuration file"
    )

    encrypt_parser = subparsers.add_parser(
        'encrypt',
        help='Encrypt a block device and store its key in Vault'
    )
    encrypt_parser.add_argument('--uuid',
                                dest="uuid",
                                help="UUID to use to reference encryption key")
    encrypt_parser.add_argument('block_device',
                                metavar='BLOCK_DEVICE', nargs=1,
                                help="Full path to block device to encrypt")
    encrypt_parser.set_defaults(func=encrypt)

    decrypt_parser = subparsers.add_parser(
        'decrypt',
        help='Decrypt a block device retrieving its key from Vault'
    )
    decrypt_parser.add_argument('uuid',
                                metavar='uuid', nargs=1,
                                help='UUID of block device to decrypt')
    decrypt_parser.set_defaults(func=decrypt)

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    try:
        if (len(vars(args)) <= 2):
            parser.print_help()
        else:
            args.func(args, get_config())
    except Exception as e:
        raise SystemExit(
            f'{args.prog}: {e}'
        )
