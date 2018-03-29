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
import uuid
import hvac
import logging
import os
import socket
import shutil
import tenacity

from six.moves import configparser

logger = logging.getLogger(__name__)

RUN_VAULTLOCKER = '/run/vaultlocker'
CONF_FILE = '/etc/vaultlocker/vaultlocker.conf'


def _vault_client(config):
    """Helper wrapper to create Vault Client"""
    client = hvac.Client(url=config.get('vault', 'url'))
    client.auth_approle(config.get('vault', 'approle'))
    return client


def _store_file_in_vault(source, client, config):
    if not os.path.exists(source):
        raise ValueError('Unable to locate source file {}'.format(source))

    source_uuid = str(uuid.uuid4())
    logger.info('Storing secret {} in vault'.format(source_uuid))

    vault_path = '{}/{}/{}'.format(config.get('vault', 'backend'),
                                   socket.gethostname(),
                                   source_uuid)

    with open(source, 'rb') as input_file:
        input_data = input_file.read()
        client.write(vault_path,
                     content=input_data,
                     source_path=source)
        stored_data = \
            client.read(vault_path)
        assert input_data == stored_data['data']['content']
        assert source == stored_data['data']['source_path']

    if not os.path.exists(RUN_VAULTLOCKER):
        os.makedirs(RUN_VAULTLOCKER)

    new_path = os.path.join(RUN_VAULTLOCKER, source_uuid)
    shutil.move(source, new_path)
    os.symlink(new_path, source)


def _retrieve_file_from_vault(target_uuid, client, config):
    new_path = os.path.join(RUN_VAULTLOCKER, target_uuid)
    if os.path.exists(new_path):
        logger.info('Secret {} already on disk, skipping'.format(target_uuid))
        return

    vault_path = '{}/{}/{}'.format(config.get('vault', 'backend'),
                                   socket.gethostname(),
                                   target_uuid)

    logger.info('Retrieving secret {} from vault'.format(target_uuid))
    stored_file = client.read(vault_path)

    if not os.path.exists(RUN_VAULTLOCKER):
        os.makedirs(RUN_VAULTLOCKER)

    with open(new_path, 'wb') as target:
        os.fchmod(target.fileno(), 0o400)
        target.write(stored_file['data']['content'])

    original_source = stored_file['data']['source_path']
    if os.path.exists(original_source):
        os.remove(original_source)
    os.symlink(new_path, original_source)


def store(args, config):
    @tenacity.retry(
        wait=tenacity.wait_fixed(1),
        stop=(tenacity.stop_after_delay(args.retry) if args.retry > 0
                else tenacity.stop_after_attempt(1)),
        retry=(tenacity.retry_if_exception(hvac.exceptions.VaultNotInitialized) |
               tenacity.retry_if_exception(hvac.exceptions.VaultDown)))
    def _do_it():
        client = _vault_client(config)
        _store_file_in_vault(args.source[0], client, config)
    _do_it()


def retrieve(args, config):
    @tenacity.retry(
        wait=tenacity.wait_fixed(1),
        stop=(tenacity.stop_after_delay(args.retry) if args.retry > 0
                else tenacity.stop_after_attempt(1)),
        retry=(tenacity.retry_if_exception(hvac.exceptions.VaultNotInitialized) |
               tenacity.retry_if_exception(hvac.exceptions.VaultDown)))
    def _do_it():
        client = _vault_client(config)
        _retrieve_file_from_vault(args.target_uuid[0], client, config)
    _do_it()


def get_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONF_FILE):
        config.read(CONF_FILE)
    return config


def main():
    parser = argparse.ArgumentParser('vaultlocker')
    parser.set_defaults(prog=parser.prog)
    subparsers = parser.add_subparsers(
        title="subcommands",
        description="valid subcommands",
        help="sub-command help",
    )
    parser.add_argument('--retry',
                        default=-1,
                        type=int,
                        help="Time in seconds to continue retrying to connect to Vault")

    store_parser = subparsers.add_parser('store', help='Store new file in vault')
    store_parser.add_argument('source',
                              metavar='SOURCE', nargs=1)
    store_parser.set_defaults(func=store)

    retrieve_parser = subparsers.add_parser('retrieve', help='Retrieve file by UUID from vault')
    retrieve_parser.add_argument('target_uuid',
                                 metavar='TARGET_UUID', nargs=1)
    retrieve_parser.set_defaults(func=retrieve)

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    try:
        args.func(args, get_config())
    except Exception as e:
        raise SystemExit(
            '{prog}: {msg}'.format(
                prog=args.prog,
                msg=e,
            )
        )
