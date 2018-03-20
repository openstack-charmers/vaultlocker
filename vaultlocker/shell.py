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
import hashlib
import hvac
import logging
import os
import socket
import time


logger = logging.getLogger(__name__)


def _vault_client(vault, token):
    """Helper wrapper to create Vault Client"""
    return hvac.Client(url=vault, token=token)


def _get_links_at_path(path):
    """Retrieve list of symbolic links from directory path"""
    files = []
    if os.path.exists(path) and os.path.isdir(path):
        for dirpath, _, filenames in os.walk(path):
            for _file in filenames:
                _path = os.path.join(dirpath, _file)
                if os.path.islink(_path):
                    target = os.path.realpath(_path)
                    if not os.path.isdir(target):
                        files.append(target)
    return files


def _get_files_at_path(path):
    """Retrieve list of files from directory path"""
    files = []
    if os.path.exists(path) and os.path.isdir(path):
        for dirpath, _, filenames in os.walk(path):
            for _file in filenames:
                _path = os.path.join(dirpath, _file)
                if not os.path.islink(_path):
                    files.append(_path)
    return files


def _make_file_link(f, destination, client):
    hasher = hashlib.sha256()
    hasher.update(f)
    digest = hasher.hexdigest()
    logger.info('Storing secret {} in vault'.format(digest))
    with open(f, 'rb') as input_file:
        input_data = input_file.read()
        client.write('secret/{}'.format(socket.gethostname()),
                     **{digest: input_data})
        stored_data = \
            client.read('secret/{}'.format(socket.gethostname()))
        assert input_data == stored_data['data'][digest]

    if not os.path.exists(destination):
        os.makedirs(destination)

    new_path = os.path.join(destination, digest)
    os.rename(f, new_path)
    os.symlink(new_path, f)


def _restore_file_at_path(f, destination, client):
    digest = os.path.basename(f)
    new_path = os.path.join(destination, digest)
    if os.path.exists(new_path):
        logger.info('Secret {} already on disk, skipping'.format(digest))
        return

    logger.info('Retrieving secret {} from vault'.format(digest))
    stored_file = client.read('secret/{}'.format(socket.gethostname()))

    if not os.path.exists(destination):
        os.makedirs(destination)

    with open(new_path, 'wb') as target:
        # TODO(jamespage): Needs permissions restriction!
        target.write(stored_file['data'][digest])


def _eat_files(args):
    client = _vault_client(args.vault, args.token)

    files_to_link = _get_links_at_path(args.source)
    files_to_lock = _get_files_at_path(args.source)

    logger.info('Storing files: {}'.format(files_to_lock))
    logger.info('Retrieving files: {}'.format(files_to_link))
    for _file in files_to_lock:
        _make_file_link(_file, args.destination, client)

    for _file in files_to_link:
        _restore_file_at_path(_file, args.destination, client)


def main():
    parser = argparse.ArgumentParser('vaultlocker')
    parser.set_defaults(prog=parser.prog)
    parser.add_argument(
        "--source",
        metavar='SOURCE',
        help="Source directory to move files from",
    )
    parser.add_argument(
        "--destination",
        metavar='DESTINATION',
        help="TMPFS to place files on",
    )
    parser.add_argument(
        "--vault",
        metavar='VAULT',
        help="Vault server URL",
    )
    parser.add_argument(
        "--token",
        metavar='TOKEN',
        help="Vault authentication token",
    )
    parser.set_defaults(func=_eat_files)

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    try:
        while True:
            args.func(args)
            time.sleep(10)
    except Exception as e:
        raise SystemExit(
            '{prog}: {msg}'.format(
                prog=args.prog,
                msg=e,
            )
        )
