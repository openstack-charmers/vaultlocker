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

import abc
from typing import Any

import hvac

KV_VERSION_1 = '1'
KV_VERSION_2 = '2'


class KVStoreBase(abc.ABC):
    """Base class for accessing a Vault KV secrets engine."""

    def __init__(self, client: hvac.Client, mount_point: str) -> None:
        self.client = client
        self.mount_point = mount_point

    @abc.abstractmethod
    def write(self, path: str, secret: dict[str, Any]) -> None:
        """Write a secret.

        :param path: path to the secret relative to the mount point
        :param secret: dictionary containing the secret data
        """

    @abc.abstractmethod
    def read(self, path: str) -> dict[str, Any]:
        """Return an unwrapped secret dictionary.

        :param path: path to the secret relative to the mount point
        :return: dictionary containing the secret data
        """

    @abc.abstractmethod
    def delete(self, path: str) -> None:
        """Permanently delete a secret.

        :param path: path to the secret relative to the mount point
        """


class KVStoreV1(KVStoreBase):
    """Access a Vault KV version 1 secrets engine."""

    def write(self, path: str, secret: dict[str, Any]) -> None:
        self.client.secrets.kv.v1.create_or_update_secret(
            path=path,
            secret=secret,
            mount_point=self.mount_point,
        )

    def read(self, path: str) -> dict[str, Any]:
        response = self.client.secrets.kv.v1.read_secret(
            path=path,
            mount_point=self.mount_point,
        )
        return response['data']

    def delete(self, path: str) -> None:
        self.client.secrets.kv.v1.delete_secret(
            path=path,
            mount_point=self.mount_point,
        )


class KVStoreV2(KVStoreBase):
    """Access a Vault KV version 2 secrets engine."""

    def write(self, path: str, secret: dict[str, Any]) -> None:
        self.client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=secret,
            mount_point=self.mount_point,
        )

    def read(self, path: str) -> dict[str, Any]:
        response = self.client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=self.mount_point,
        )
        return response['data']['data']

    def delete(self, path: str) -> None:
        self.client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=path,
            mount_point=self.mount_point,
        )


class KVStore:
    """Factory for KV store implementations."""

    _registry = {
        KV_VERSION_1: KVStoreV1,
        KV_VERSION_2: KVStoreV2,
    }

    @classmethod
    def get_store(
        cls, client: hvac.Client, mount_point: str, kv_version: str
    ) -> KVStoreBase:
        """Return a KV store implementation for the given version.

        :param client: Authenticated hvac.Client.
        :param mount_point: Vault secrets-engine mount point.
        :param kv_version: KV secrets engine version.
        :returns: KVStoreBase: configured store implementation.
        :raises ValueError: if kv_version is not a supported value.
        """
        store_class = cls._registry.get(kv_version)
        if store_class is None:
            raise ValueError(
                "Unsupported kv_version '{}'".format(kv_version)
            )
        return store_class(client, mount_point)
