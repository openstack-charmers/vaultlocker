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

"""
test_vault
----------------------------------

Tests for `vaultlocker.vault` module.
"""

from unittest import mock

import hvac

from vaultlocker.tests.unit import base
from vaultlocker import vault


class TestKVStoreV1(base.TestCase):

    def setUp(self):
        super().setUp()
        self.client = mock.MagicMock()
        self.store = vault.KVStoreV1(self.client, 'vaultlocker-v1')

    def test_write(self):
        self.store.write('host/device', {'dmcrypt_key': 'test-key'})

        (
            self.client.secrets.kv.v1
            .create_or_update_secret
            .assert_called_once_with(
                path='host/device',
                secret={'dmcrypt_key': 'test-key'},
                mount_point='vaultlocker-v1',
            )
        )

    def test_read_unwraps_data(self):
        self.client.secrets.kv.v1.read_secret.return_value = {
            'data': {
                'dmcrypt_key': 'test-key',
            },
        }

        self.assertEqual(
            {'dmcrypt_key': 'test-key'},
            self.store.read('host/device'),
        )

    def test_delete(self):
        self.store.delete('host/device')

        (
            self.client.secrets.kv.v1.delete_secret
            .assert_called_once_with(
                path='host/device',
                mount_point='vaultlocker-v1',
            )
        )

    def test_read_raises(self):
        self.client.secrets.kv.v1.read_secret.side_effect = (
            hvac.exceptions.InvalidPath('missing')
        )

        self.assertRaises(
            hvac.exceptions.InvalidPath,
            self.store.read,
            'host/device',
        )


class TestKVStoreV2(base.TestCase):

    def setUp(self):
        super().setUp()
        self.client = mock.MagicMock()
        self.store = vault.KVStoreV2(self.client, 'vaultlocker-v2')

    def test_write(self):
        self.store.write(
            'host/device',
            {'dmcrypt_key': 'test-key'},
        )

        (
            self.client.secrets.kv.v2
            .create_or_update_secret
            .assert_called_once_with(
                path='host/device',
                secret={'dmcrypt_key': 'test-key'},
                mount_point='vaultlocker-v2',
            )
        )

    def test_read_unwraps_nested_data(self):
        self.client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {
                'data': {
                    'dmcrypt_key': 'test-key',
                },
                'metadata': {
                    'version': 1,
                },
            },
        }

        self.assertEqual(
            {'dmcrypt_key': 'test-key'},
            self.store.read('host/device'),
        )

    def test_delete(self):
        self.store.delete('host/device')

        (
            self.client.secrets.kv.v2
            .delete_metadata_and_all_versions
            .assert_called_once_with(
                path='host/device',
                mount_point='vaultlocker-v2',
            )
        )

    def test_read_raises(self):
        self.client.secrets.kv.v2.read_secret_version.side_effect = (
            hvac.exceptions.InvalidPath('missing')
        )

        self.assertRaises(
            hvac.exceptions.InvalidPath,
            self.store.read,
            'host/device',
        )


class TestKVStoreFactory(base.TestCase):

    def test_get_store_v1(self):
        client = mock.MagicMock()

        store = vault.KVStore.get_store(
            client=client,
            mount_point='vaultlocker-v1',
            kv_version=vault.KV_VERSION_1,
        )

        self.assertIsInstance(store, vault.KVStoreV1)
        self.assertIs(store.client, client)
        self.assertEqual(store.mount_point, 'vaultlocker-v1')

    def test_get_store_v2(self):
        client = mock.MagicMock()

        store = vault.KVStore.get_store(
            client=client,
            mount_point='vaultlocker-v2',
            kv_version=vault.KV_VERSION_2,
        )

        self.assertIsInstance(store, vault.KVStoreV2)
        self.assertIs(store.client, client)
        self.assertEqual(store.mount_point, 'vaultlocker-v2')

    def test_get_store_rejects_unsupported_version(self):
        with self.assertRaises(ValueError) as error:
            vault.KVStore.get_store(
                client=mock.MagicMock(),
                mount_point='vaultlocker-test',
                kv_version='3',
            )

        self.assertIn("Unsupported kv_version '3'", str(error.exception))
