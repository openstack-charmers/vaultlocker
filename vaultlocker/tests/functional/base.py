# -*- coding: utf-8 -*-

# Copyright 2010-2011 OpenStack Foundation
# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
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

import hvac
import os
import shutil
import tempfile
from unittest import mock
import uuid

from oslotest import base

from vaultlocker import shell


KV1_POLICY = '''
path "{backend}/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
'''

KV2_POLICY = '''
path "{backend}/data/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
path "{backend}/metadata/*" {{
  capabilities = ["read", "delete", "list"]
}}
'''


class VaultlockerFuncBaseTestCase(base.BaseTestCase):

    """Test case base class for all functional tests."""

    #: KV secrets engine version under test.
    kv_version = '1'

    def setUp(self):
        super(VaultlockerFuncBaseTestCase, self).setUp()
        self.vault_client = None

        self.vault_addr = os.environ.get('PIFPAF_VAULT_ADDR')
        self.root_token = os.environ.get('PIFPAF_ROOT_TOKEN')

        self.test_uuid = str(uuid.uuid4())
        self.vault_backend = 'vaultlocker-test-{}'.format(self.test_uuid)
        self.vault_policy = 'vaultlocker-policy-{}'.format(self.test_uuid)
        self.vault_approle = 'vaultlocker-approle-{}'.format(self.test_uuid)

        if not self.vault_addr or not self.root_token:
            self.skipTest('Vault not running')

        self.vault_client = hvac.Client(url=self.vault_addr,
                                        token=self.root_token)

        self.vault_client.sys.enable_secrets_engine(
            backend_type='kv',
            path=self.vault_backend,
            description='vaultlocker test backend',
            options={'version': self.kv_version},
        )

        try:
            self.vault_client.sys.enable_auth_method('approle')
        except hvac.exceptions.InvalidRequest:
            pass

        policy = KV2_POLICY if self.kv_version == '2' else KV1_POLICY
        self.vault_client.sys.create_or_update_policy(
            name=self.vault_policy,
            policy=policy.format(backend=self.vault_backend),
        )

        self.vault_client.auth.approle.create_or_update_approle(
            role_name=self.vault_approle,
            token_ttl='60s',
            token_max_ttl='60s',
            token_policies=[self.vault_policy],
            bind_secret_id=True,
        )
        self.approle_uuid = self.vault_client.auth.approle.read_role_id(
            role_name=self.vault_approle,
        )['data']['role_id']
        self.secret_id = self.vault_client.auth.approle.generate_secret_id(
            role_name=self.vault_approle,
        )['data']['secret_id']

        self.test_config = {
            'vault': {
                'url': self.vault_addr,
                'approle': self.approle_uuid,
                'secret_id': self.secret_id,
                'backend': self.vault_backend,
                'kv_version': self.kv_version,
            }
        }
        self.config = mock.MagicMock()
        self.config.get.side_effect = \
            lambda s, k, **kwargs: self.test_config.get(s, {}).get(
                k, kwargs.get('fallback')
            )

        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)
        self.config_path = os.path.join(self.temp_dir, 'vaultlocker.conf')

    def tearDown(self):
        super(VaultlockerFuncBaseTestCase, self).tearDown()
        if self.vault_client:
            self.vault_client.sys.disable_secrets_engine(
                path=self.vault_backend,
            )
            self.vault_client.sys.delete_policy(name=self.vault_policy)

    def vault_store(self):
        """Return a KV store configured for this test's backend."""
        return shell._vault_store(self.vault_client, self.config)

    def secret_path(self, device_uuid):
        """Return the secret path used for a device UUID."""
        return shell._vault_secret_path(device_uuid, self.config)
