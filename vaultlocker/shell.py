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
import json
import logging
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import uuid

import hvac
import tenacity

from vaultlocker import boot_unlock
from vaultlocker import dmcrypt
from vaultlocker import exceptions
from vaultlocker.exit_codes import ExitCode
from vaultlocker import vault

logger = logging.getLogger(__name__)

DEFAULT_CONF_FILE = '/etc/vaultlocker/vaultlocker.conf'

REQUIRED_VAULT_SETTINGS = ('url', 'approle', 'secret_id', 'backend')

#: Suffix of the sidecar file pinning the Vault cluster identity.
CLUSTER_ID_SUFFIX = '.cluster-id'


def _vault_client(config):
    """Create an unauthenticated Vault client."""
    return hvac.Client(
        url=config.get('vault', 'url'),
        verify=config.get('vault', 'ca_bundle', fallback=True),
    )


def _login_to_vault(client, config):
    """Authenticate a Vault client with AppRole credentials."""
    client.auth.approle.login(
        role_id=config.get('vault', 'approle'),
        secret_id=config.get('vault', 'secret_id'),
    )


def _cluster_pin_path(config_path):
    """Return the cluster pin path for a configuration file."""
    return '{}{}'.format(config_path, CLUSTER_ID_SUFFIX)


def _read_cluster_pin(path):
    """Read the cluster pin from a sidecar."""
    try:
        with open(path, 'r', encoding='utf-8') as sidecar:
            value = sidecar.read().strip()
    except (OSError, UnicodeError) as read_error:
        raise exceptions.ClusterIdentityError(
            'Unable to read Vault cluster identity {}: {}'.format(
                path, read_error,
            )
        ) from read_error
    if not value:
        raise exceptions.ClusterIdentityError(
            'Invalid Vault cluster identity in {}'.format(path)
        )
    return value


def _create_cluster_pin(path, cluster_id):
    """Create a complete pin without replacing an existing one."""
    path = Path(path)
    try:
        # For almost all runs, the pin already exists.
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            return _read_cluster_pin(path)

        fd, temporary_name = tempfile.mkstemp(dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as temp_file:
                os.fchmod(temp_file.fileno(), 0o600)
                temp_file.write(cluster_id)

            try:
                os.link(temporary_path, path)
            except FileExistsError:
                # Another process created it first.
                return _read_cluster_pin(path)

            return cluster_id
        finally:
            temporary_path.unlink(missing_ok=True)
    except (OSError, UnicodeError) as error:
        raise exceptions.ClusterIdentityError(
            'Unable to create Vault cluster identity {}: {}'.format(
                path, error,
            )
        ) from error


def _verify_cluster_identity(client, config_path):
    """Pin the Vault cluster on first use and verify later connections."""
    observed_id = vault.get_cluster_id(client)

    pin_path = _cluster_pin_path(config_path)
    pinned_id = _create_cluster_pin(pin_path, observed_id)

    if pinned_id != observed_id:
        raise exceptions.ClusterIdentityMismatchError(
            pinned_id, observed_id,
        )


def _get_kv_version(config):
    """Return the configured Vault KV version.

    :param config: configparser object of vaultlocker config
    :returns: str: KV version ('1' or '2')
    :raises exceptions.ConfigurationError: if the value is not '1' or '2'
    """
    version = config.get('vault', 'kv_version', fallback=vault.KV_VERSION_1)
    if version not in (vault.KV_VERSION_1, vault.KV_VERSION_2):
        raise exceptions.ConfigurationError(
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

    stored_key = stored_data.get('dmcrypt_key') if isinstance(
        stored_data, dict) else None
    if not stored_key:
        raise exceptions.ManagedKeyInvalidError(vault_path)

    if key != stored_key:
        raise exceptions.VaultKeyMismatch(vault_path)


def _read_existing_key(key_file):
    """Read an existing LUKS key from a file or standard input.

    Prompt without echo when standard input is an interactive terminal.

    :param: key_file: file path, or None to use standard input.
    :returns: bytes containing the existing key.
    :raises exceptions.ExistingKeyInvalidError: if the key file cannot be
        read, or the resulting key material is empty.
    """
    if key_file:
        try:
            with open(key_file, 'rb') as key_source:
                key = key_source.read()
        except OSError as read_error:
            raise exceptions.ExistingKeyInvalidError(
                'Unable to read existing key file {}: {}'.format(
                    key_file, read_error,
                )
            )
    elif sys.stdin.isatty():
        key = getpass.getpass(
            'Existing LUKS passphrase: '
        ).encode('utf-8')
    else:
        key = sys.stdin.buffer.read()

    if not key:
        raise exceptions.ExistingKeyInvalidError(
            'Existing LUKS key cannot be empty'
        )

    return key


def _mapper_path(block_uuid):
    """Return the dm-crypt mapper path for a LUKS UUID."""
    return '/dev/mapper/crypt-{}'.format(block_uuid)


def _by_uuid_path(block_uuid):
    """Return the by-UUID path for a LUKS UUID."""
    return '/dev/disk/by-uuid/{}'.format(block_uuid)


def _register_boot_unlock(block_device, block_uuid, config_path):
    """Register the device for boot-time unlocking."""
    try:
        boot_unlock.register(block_uuid, config_path)
    except (subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            OSError) as boot_error:
        logger.error(
            'Registering boot unlock for %s failed: %s',
            block_uuid,
            _subprocess_error_output(boot_error),
        )
        raise exceptions.BootConfigError(
            block_device, _subprocess_error_output(boot_error),
        )


def _subprocess_error_output(error):
    """Return output from a subprocess error."""
    output = getattr(error, 'output', None)
    if output is None:
        output = getattr(error, 'stderr', None)
    return output if output else str(error)


def _subprocess_error_returncode(error):
    """Return a subprocess error's exit code, if available."""
    return getattr(error, 'returncode', None)


# cryptsetup returns 1 when luksUUID finds no LUKS header.
_NO_LUKS_HEADER_EXIT_CODE = 1


def _get_existing_luks_uuid(block_device):
    """Return the device UUID, or None when it has no LUKS header."""
    try:
        return dmcrypt.luks_uuid(block_device)
    except subprocess.CalledProcessError as luks_error:
        if luks_error.returncode == _NO_LUKS_HEADER_EXIT_CODE:
            return None
        raise exceptions.LuksValidationError(
            block_device,
            'Unable to determine whether {} already has a LUKS header '
            '(cryptsetup exit code {}): {}'.format(
                block_device,
                luks_error.returncode,
                _subprocess_error_output(luks_error),
            ),
        )
    except subprocess.TimeoutExpired as luks_error:
        raise exceptions.LuksValidationError(
            block_device,
            'Timed out determining whether {} already has a LUKS '
            'header: {}'.format(
                block_device, _subprocess_error_output(luks_error),
            ),
        )


def _key_unlocks_device(key, block_device):
    """Return whether the key unlocks the device."""
    try:
        return dmcrypt.luks_test_key(key, block_device)
    except (subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as e:
        raise exceptions.LuksValidationError(
            block_device,
            'Unable to determine whether the key unlocks {}: {}'.format(
                block_device, _subprocess_error_output(e),
            ),
        ) from e


def _read_vault_key(store, path):
    """Read a Vault key, or return None when the path does not exist."""
    try:
        stored_data = store.read(path)
    except hvac.exceptions.InvalidPath:
        return None

    key = stored_data.get('dmcrypt_key') if isinstance(
        stored_data, dict) else None
    if not key:
        raise exceptions.ManagedKeyInvalidError(
            '{}/{}'.format(store.mount_point, path)
        )

    return key


def _ensure_vault_key(store, path, expected_key):
    """Ensure Vault has the expected key without overwriting data."""
    current_key = _read_vault_key(store, path)
    if current_key is None:
        _store_and_validate_key(store, path, expected_key)
        return

    if current_key != expected_key:
        raise exceptions.VaultKeyMismatch(
            '{}/{}'.format(store.mount_point, path)
        )


def _open_and_register_device(block_device, block_uuid, key, config_path):
    """Open the mapper if needed and register it for boot."""
    if not _device_exists(block_uuid):
        try:
            dmcrypt.luks_open(key, block_uuid, block_device)
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired) as open_error:
            raise exceptions.MapperOpenError(
                block_device, _subprocess_error_output(open_error),
            )

    _register_boot_unlock(block_device, block_uuid, config_path)

    return {
        "luks_uuid": block_uuid,
        "mapper_path": _mapper_path(block_uuid),
    }


def _open_existing_managed_device(args, client, config, block_device,
                                  block_uuid):
    """Reuse an encrypted device when its Vault key can unlock it."""
    if args.uuid and args.uuid != block_uuid:
        raise exceptions.LuksValidationError(
            block_device,
            'device already contains a LUKS header with UUID {} which does '
            'not match the requested UUID {}'.format(block_uuid, args.uuid),
        )

    store = _vault_store(client, config)
    path = _vault_secret_path(block_uuid, config)
    vault_key = _read_vault_key(store, path)

    if vault_key is None:
        raise exceptions.LuksValidationError(
            block_device,
            'device already contains a LUKS header but no '
            'vaultlocker-managed key is present in Vault',
        )

    if not _key_unlocks_device(vault_key, block_device):
        raise exceptions.LuksValidationError(
            block_device,
            'device already contains a LUKS header but the managed key '
            'does not unlock it',
        )

    return _open_and_register_device(
        block_device, block_uuid, vault_key, args.config,
    )


def _format_completed(block_device, block_uuid, key):
    """Check whether a failed or timed-out format completed."""
    try:
        current_uuid = dmcrypt.luks_uuid(block_device)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

    if current_uuid != block_uuid:
        return False

    return _key_unlocks_device(key, block_device)


def _format_device(args, client, config, block_device, block_uuid, key):
    """Store the key, format the device, and finish its setup."""
    store = _vault_store(client, config)
    path = _vault_secret_path(block_uuid, config)

    _ensure_vault_key(store, path, key)

    try:
        dmcrypt.luks_format(key, block_device, block_uuid)
    except (subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as luks_error:
        if not _format_completed(block_device, block_uuid, key):
            logger.error(
                'LUKS formatting %s failed with error code: %s\n'
                'LUKS output: %s',
                block_device,
                _subprocess_error_returncode(luks_error),
                _subprocess_error_output(luks_error),
            )
            raise exceptions.LuksFormatError(
                block_device, _subprocess_error_output(luks_error),
            )
        logger.warning(
            'cryptsetup luksFormat for %s reported an error (%s) but the '
            'device now has the expected UUID and key; continuing',
            block_device, luks_error,
        )

    if not boot_unlock.running_in_snap():
        try:
            # Ask udev to create the by-UUID link used during boot.
            dmcrypt.udevadm_rescan(block_device)
            dmcrypt.udevadm_settle(block_uuid)
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired) as udev_error:
            logger.warning(
                'udev processing for %s failed with error code: %s\n'
                'udev output: %s',
                block_device,
                _subprocess_error_returncode(udev_error),
                _subprocess_error_output(udev_error),
            )
            if not os.path.exists(_by_uuid_path(block_uuid)):
                logger.warning(
                    'by-uuid symlink for %s not present yet; udev should '
                    'create it shortly',
                    block_uuid,
                )

    return _open_and_register_device(
        block_device, block_uuid, key, args.config,
    )


def _encrypt_block_device(args, client, config, new_uuid,
                          new_key):
    """Encrypt a plain device or reuse an encrypted one.

    :param: args: argparser generated cli arguments
    :param: client: hvac.Client for Vault access
    :param: config: configparser object of vaultlocker config
    :param: new_uuid: UUID to use when formatting a plain device
    :param: new_key: key to use when formatting a plain device
    :returns: dict containing the LUKS UUID and mapper path
    """
    block_device = args.block_device[0]

    existing_uuid = _get_existing_luks_uuid(block_device)
    if existing_uuid is not None:
        return _open_existing_managed_device(
            args, client, config, block_device, existing_uuid,
        )

    return _format_device(
        args, client, config, block_device, new_uuid, new_key,
    )


def _enroll_block_device(args, client, config, get_operator_key):
    """Add or reuse a Vault-managed key on an existing LUKS device.

    :param: args: argparser generated cli arguments
    :param: client: hvac.Client for Vault access
    :param: config: configparser object of vaultlocker config
    :param: get_operator_key: callable that returns the  device's existing key
    :returns: dict containing the LUKS UUID and mapper path
    """
    block_device = args.block_device[0]

    try:
        block_uuid = dmcrypt.luks_uuid(block_device)
    except (subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as luks_error:
        raise exceptions.LuksValidationError(
            block_device, _subprocess_error_output(luks_error),
        )

    store = _vault_store(client, config)
    path = _vault_secret_path(block_uuid, config)
    vault_key = _read_vault_key(store, path)

    if vault_key is not None and _key_unlocks_device(vault_key, block_device):
        # Reuse an enrolled key without asking for the current key.
        return _open_and_register_device(
            block_device, block_uuid, vault_key, args.config,
        )

    # Read the operator's key only when the device needs to change.
    current_key = get_operator_key()
    if not _key_unlocks_device(current_key, block_device):
        raise exceptions.ExistingKeyInvalidError(
            'Existing key does not unlock {}'.format(block_device)
        )

    if vault_key is None:
        vault_key = dmcrypt.generate_key()
        _store_and_validate_key(store, path, vault_key)

    try:
        dmcrypt.luks_add_key(current_key, vault_key, block_device)
    except (subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as luks_error:
        logger.warning(
            'luksAddKey for %s reported an error (%s); checking whether '
            'the managed key was added despite the error before failing',
            block_device, luks_error,
        )

    if not _key_unlocks_device(vault_key, block_device):
        raise exceptions.LuksAddKeyError(
            block_device,
            'Vaultlocker managed key unable to unlock the device',
        )

    return _open_and_register_device(
        block_device, block_uuid, vault_key, args.config,
    )


def _decrypt_block_device(args, client, config):
    """Open a LUKS/dm-crypt encrypted block device.

    The device's dm-crypt key is retrieved from Vault.

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

    vault_key = _read_vault_key(store, path)
    if vault_key is None:
        raise exceptions.ManagedKeyNotFoundError(
            '{}/{}'.format(store.mount_point, path)
        )

    try:
        dmcrypt.luks_open(vault_key, block_uuid)
    except (subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as open_error:
        raise exceptions.MapperOpenError(
            'UUID={}'.format(block_uuid),
            _subprocess_error_output(open_error),
        )


def _device_exists(block_uuid):
    """Checks if the device already exists."""
    path = _mapper_path(block_uuid)
    logger.info('Checking if %s exists.', path)
    return os.path.exists(path)


def _do_it_with_persistence(func, args, config,
                            fail_on_cluster_mismatch=True):
    """Run an operation, retrying temporary Vault availability failures.

    :param: func: function to attempt to execute
    :param: args: argparser generated cli arguments
    :param: config: configparser object of vaultlocker config
    :param: fail_on_cluster_mismatch: whether to stop on a mismatch
    :returns: the operation result
    """
    @tenacity.retry(
        wait=tenacity.wait_fixed(1),
        reraise=True,
        stop=(
            tenacity.stop_after_delay(args.retry) if args.retry > 0
            else tenacity.stop_after_attempt(1)
            ),
        retry=(
            tenacity.retry_if_exception_type(
                hvac.exceptions.VaultNotInitialized) |
            tenacity.retry_if_exception_type(hvac.exceptions.VaultDown)
            )
        )
    def _do_it():
        client = _vault_client(config)
        _login_to_vault(client, config)
        try:
            _verify_cluster_identity(client, args.config)
        except exceptions.ClusterIdentityMismatchError as mismatch_error:
            if fail_on_cluster_mismatch:
                raise
            logger.warning('Cluster identity mismatch: %s', mismatch_error)
        return func(args, client, config)

    try:
        return _do_it()
    except hvac.exceptions.VaultError as vault_error:
        raise exceptions.VaultConnectionError(vault_error) from vault_error


def encrypt(args, config):
    """Encrypt and open handler.

    Generate one UUID and key, then reuse them for every retry.

    :param: args: argparser generated cli arguments
    :param: config: configparser object of vaultlocker config
    """
    new_uuid = args.uuid or str(uuid.uuid4())
    new_key = dmcrypt.generate_key()

    encrypt_device = functools.partial(
        _encrypt_block_device,
        new_uuid=new_uuid,
        new_key=new_key,
    )

    return _do_it_with_persistence(encrypt_device, args, config)


def enroll(args, config):
    """Enroll and open handler.

    Read the operator key only when the device needs to change.

    :param: args: argparser generated cli arguments
    :param: config: configparser object of vaultlocker config
    """
    operator_key_cache = {}

    def get_operator_key():
        if 'value' not in operator_key_cache:
            operator_key_cache['value'] = _read_existing_key(
                args.existing_key_file,
            )
        return operator_key_cache['value']

    enroll_device = functools.partial(
        _enroll_block_device,
        get_operator_key=get_operator_key,
    )

    return _do_it_with_persistence(
        enroll_device,
        args,
        config,
    )


def decrypt(args, config):
    """Decrypt and open handler.

    The device's dm-crypt key is retrieved from Vault.

    :param: args: argparser generated cli arguments
    :param: config: configparser object of vaultlocker config
    """
    return _do_it_with_persistence(
        _decrypt_block_device, args, config,
        fail_on_cluster_mismatch=False,
    )


def get_config(config_path):
    """Read and validate a vaultlocker configuration file.

    :param: config_path: path to the configuration file
    :returns: configparser. Parsed configuration options
    :raises exceptions.ConfigurationError: if the file is invalid
    """
    if any(character.isspace() for character in config_path):
        raise ValueError(
            'Configuration path cannot contain whitespace'
        )

    config = configparser.ConfigParser()

    try:
        with open(config_path, 'r') as config_file:
            config.read_file(config_file)

        for option in REQUIRED_VAULT_SETTINGS:
            value = config.get('vault', option)
            if not value.strip():
                raise exceptions.ConfigurationError(
                    "Configuration option [vault] {} cannot be empty".format(
                        option,
                    )
                )

        _get_kv_version(config)
    except exceptions.ConfigurationError:
        raise
    except (OSError, configparser.Error) as config_error:
        raise exceptions.ConfigurationError(
            "Unable to load configuration {}: {}".format(
                config_path, config_error,
            )
        ) from config_error

    return config


def main():
    """Run the command and print structured results."""
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

    logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)

    try:
        if not hasattr(args, 'func'):
            parser.print_help()
        else:
            result = args.func(args, get_config(args.config))
            if isinstance(result, dict):
                print(json.dumps(result))
    except exceptions.VaultlockerException as vault_error:
        print(
            json.dumps({
                "error": str(vault_error),
            }),
            file=sys.stderr,
        )
        sys.exit(ExitCode.HANDLED_FAILURE)
    except Exception as error:
        print(
            json.dumps({
                "error": str(error),
            }),
            file=sys.stderr,
        )
        sys.exit(ExitCode.UNEXPECTED_FAILURE)
