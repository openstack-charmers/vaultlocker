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
import time


logger = logging.getLogger(__name__)

RUN_VAULTLOCKER = '/run/vaultlocker'


def _vault_client(vault, approle):
    """Helper wrapper to create Vault Client"""
    client = hvac.Client(url=vault)
    client.auth_approle(approle)
    return client


def _store_file_in_vault(source, client):
    source_uuid = str(uuid.uuid4())
    logger.info('Storing secret {} in vault'.format(source_uuid))
    with open(source, 'rb') as input_file:
        input_data = input_file.read()
        client.write('secret/{}/{}'.format(socket.gethostname(),
                                           source_uuid),
                     content=input_data,
                     path=source)
        stored_data = \
            client.read('secret/{}/{}'.format(socket.gethostname(),
                                              source_uuid))
        assert input_data == stored_data['data']['content']
        assert source == stored_data['data']['path']

    if not os.path.exists(RUN_VAULTLOCKER):
        os.makedirs(RUN_VAULTLOCKER)

    new_path = os.path.join(RUN_VAULTLOCKER, source_uuid)
    os.rename(source, new_path)
    os.symlink(new_path, source)


def _retrieve_file_from_vault(target_uuid, client):
    new_path = os.path.join(RUN_VAULTLOCKER, target_uuid)
    if os.path.exists(new_path):
        logger.info('Secret {} already on disk, skipping'.format(target_uuid))
        return

    logger.info('Retrieving secret {} from vault'.format(target_uuid))
    stored_file = client.read('secret/{}/{}'.format(socket.gethostname(),
                                                    target_uuid))

    if not os.path.exists(RUN_VAULTLOCKER):
        os.makedirs(RUN_VAULTLOCKER)

    with open(new_path, 'wb') as target:
        os.fchmod(target.fileno(), 0o400)
        target.write(stored_file['data']['content'])

    original_source = stored_file['data']['path']
    if os.path.exists(original_source):
        os.remove(original_source)
    os.symlink(new_path, original_source)


def store(args):
    client = _vault_client(args.vault_url, args.approle)
    _store_file_in_vault(args.source, client)


def retrieve(args):
    client = _vault_client(args.vault_url, args.approle)
    _retrieve_file_from_vault(args.target_uuid, client)


def main():
    parser = argparse.ArgumentParser('vaultlocker')
    parser.set_defaults(prog=parser.prog)
    parser.add_argument(
        "--vault-url",
        metavar='VAULT_URL',
        help="Vault server URL",
    )
    parser.add_argument(
        "--approle",
        metavar='approle',
        help="Vault Application Role",
    )

    subparsers = parser.add_subparsers(
        title="subcommands",
        description="valid subcommands",
        help="sub-command help",
    )

    store_parser = subparsers.add_parser('store', help='Store new file in vault')
    store_parser.add_argument(
        "--source",
        metavar='source',
        help="File to store and manage using Vault",
    )
    store_parser.set_defaults(func=store)

    retrieve_parser = subparsers.add_parser('retrieve', help='Retrieve file from vault')
    retrieve_parser.add_argument(
        "--target-uuid",
        metavar='target_uuid',
        help="UUID of file to retrieve from Vault",
    )
    retrieve_parser.set_defaults(func=retrieve)

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    try:
        args.func(args)
    except Exception as e:
        raise SystemExit(
            '{prog}: {msg}'.format(
                prog=args.prog,
                msg=e,
            )
        )
