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

import argparse
import configparser
import functools
import getpass
import logging
import os
import platform
import socket
import subprocess
import sys
import uuid

import hvac
import tenacity

from vaultlocker import dmcrypt
from vaultlocker import exceptions
from vaultlocker import systemd
from vaultlocker import vault

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
            "Invalid kv_version '{}' in vaultlocker config; "
            "must be '{}' or '{}'".format(
                version, vault.KV_VERSION_1, vault.KV_VERSION_2
            )
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
            'Unable to determine hostname: {}'.format(hostname_error)
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
    return '{}/{}'.format(
        get_hostname(config),
        device_uuid,
    )


def _get_vault_path(device_uuid, config):
    """Return the complete Vault path.

    :param device_uuid: String of the device UUID
    :param config: configparser object of vaultlocker config
    :returns: Path in ``<mount>/<hostname>/<uuid>`` form.
    """
    return '{}/{}'.format(
        _vault_mount_point(config),
        _vault_secret_path(device_uuid, config),
    )


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


def _store_and_validate_key(store, path, key):
    """Store a dm-crypt key in Vault and validate if it was stored."""
    vault_path = '{}/{}'.format(
        store.mount_point,
        path,
    )

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

    if key != stored_data['dmcrypt_key']:
        raise exceptions.VaultKeyMismatch(vault_path)


def _read_existing_key(key_file):
    """Read an existing LUKS key from a file or standard input.

    Prompt without echo when standard input is an interactive terminal.

    :param: key_file: file path, or None to use standard input.
    :returns: bytes containing the existing key.
    """
    if key_file:
        with open(key_file, 'rb') as key_source:
            key = key_source.read()
    elif sys.stdin.isatty():
        key = getpass.getpass(
            'Existing LUKS passphrase: '
        ).encode('utf-8')
    else:
        key = sys.stdin.buffer.read()

    if not key:
        raise ValueError('Existing LUKS key cannot be empty')

    return key


def _get_or_create_managed_key(store, path):
    """Return an existing managed key or create one and store it in Vault.

    :param: store: Vault key-value store object.
    :param: path: path to the managed key in Vault.
    :returns: managed key as str
    """
    try:
        stored_data = store.read(path)
    except hvac.exceptions.InvalidPath:
        key = dmcrypt.generate_key()
        _store_and_validate_key(store, path, key)
        return key

    if (
            not isinstance(stored_data, dict) or
            not stored_data.get('dmcrypt_key')
    ):
        raise ValueError(
            'Vault secret at {}/{} does not contain dmcrypt_key'.format(
                store.mount_point,
                path,
            )
        )

    return stored_data['dmcrypt_key']


def _enroll_block_device(args, client, config, existing_key):
    """Add a Vault-managed key to an existing LUKS device.

    :param: args: argparser generated CLI arguments.
    :param: client: hvac.Client for Vault access.
    :param: config: configparser object of vaultlocker config.
    :param: existing_key: existing key used to unlock the device.
    """
    block_device = args.block_device[0]

    try:
        block_uuid = dmcrypt.luks_uuid(block_device)

        if not dmcrypt.luks_test_key(existing_key, block_device):
            raise ValueError(
                'Existing key does not unlock {}'.format(block_device)
            )
    except subprocess.CalledProcessError as luks_error:
        raise exceptions.LUKSFailure(
            block_device,
            luks_error.output,
        )

    path = _vault_secret_path(block_uuid, config)
    store = _vault_store(client, config)
    key = _get_or_create_managed_key(store, path)

    try:
        if not dmcrypt.luks_test_key(key, block_device):
            dmcrypt.luks_add_key(
                existing_key,
                key,
                block_device,
            )

            if not dmcrypt.luks_test_key(key, block_device):
                raise exceptions.LUKSFailure(
                    block_device,
                    'Vaultlocker managed key unable to unlock the device',
                )

        if not _device_exists(block_uuid):
            dmcrypt.luks_open(key, block_uuid)

    except subprocess.CalledProcessError as luks_error:
        logger.error(
            'LUKS enrollment for %s failed with error code: %s\n'
            'LUKS output: %s',
            block_device,
            luks_error.returncode,
            luks_error.output,
        )
        raise exceptions.LUKSFailure(
            block_device,
            luks_error.output,
        )

    systemd.enable(
        'vaultlocker-decrypt@{}.service'.format(block_uuid)
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
    vault_path = '{}/{}'.format(
        _vault_mount_point(config),
        path,
    )
    store = _vault_store(client, config)

    # NOTE: store and validate key before trying to encrypt disk
    _store_and_validate_key(store, path, key)

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

    systemd.enable('vaultlocker-decrypt@{}.service'.format(block_uuid))


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
            'Unable to locate key for {}'.format(block_uuid)
        )

    key = stored_data['dmcrypt_key']

    dmcrypt.luks_open(key, block_uuid)


def _device_exists(block_uuid):
    """Checks if the device already exists."""
    handle = 'crypt-{}'.format(block_uuid)
    path = "/dev/mapper/{}".format(handle)
    logger.info('Checking if %s exists.', path)
    return os.path.exists(path)


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


def enroll(args, config):
    """Enroll and open handler.

    :param: args: argparser generated CLI arguments.
    :param: config: configparser object of vaultlocker config.
    """
    # Read the existing key once because stdin cannot be reread during retries,
    # then bind it to the enrollment operation.
    existing_key = _read_existing_key(args.existing_key_file)

    enroll_operation = functools.partial(
        _enroll_block_device,
        existing_key=existing_key,
    )

    _do_it_with_persistence(
        enroll_operation,
        args,
        config,
    )


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
    if os.path.exists(config_path):
        config.read(config_path)
    else:
        raise FileNotFoundError(
            "Configuration file not found: {}".format(config_path)
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

    enroll_parser = subparsers.add_parser(
        'enroll',
        help='Add a Vault-managed key to an existing LUKS device'
    )
    enroll_parser.add_argument(
        '--existing-key-file',
        help=(
            "Existing LUKS key file. If omitted, read from stdin or prompt "
            "when run interactively"
        )
    )
    enroll_parser.add_argument(
        'block_device',
        metavar='BLOCK_DEVICE',
        nargs=1,
        help='Full path to the existing LUKS device'
    )
    enroll_parser.set_defaults(func=enroll)

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
            args.func(args, get_config(args.config))
    except Exception as e:
        raise SystemExit(
            '{prog}: {msg}'.format(
                prog=args.prog,
                msg=e,
            )
        )
