
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

import os
import uuid
from unittest import mock

import hvac
from oslotest import base

TEST_POLICY = '''
path "{backend}/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
'''


class VaultlockerFuncBaseTestCase(base.BaseTestCase):

    """Test case base class for all functional tests."""

    def setUp(self):
        super().setUp()
        self.vault_client = None

        self.vault_addr = os.environ.get('PIFPAF_VAULT_ADDR')
        self.root_token = os.environ.get('PIFPAF_ROOT_TOKEN')

        self.test_uuid = str(uuid.uuid4())
        self.vault_backend = f'vaultlocker-test-{self.test_uuid}'
        self.vault_policy = f'vaultlocker-policy-{self.test_uuid}'
        self.vault_approle = f'vaultlocker-approle-{self.test_uuid}'

        if not self.vault_addr or not self.root_token:
            self.skipTest('Vault not running')

        self.vault_client = hvac.Client(url=self.vault_addr,
                                        token=self.root_token)

        self.vault_client.sys.enable_secrets_engine(
            backend_type='kv',
            path=self.vault_backend,
            description='vaultlocker test backend',
            options={'version': '1'},
        )

        try:
            self.vault_client.sys.enable_auth_method('approle')
        except hvac.exceptions.InvalidRequest:
            pass

        self.vault_client.sys.create_or_update_policy(
            name=self.vault_policy,
            policy=TEST_POLICY.format(backend=self.vault_backend),
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
            }
        }
        self.config = mock.MagicMock()
        self.config.get.side_effect = \
            lambda s, k, **kwargs: self.test_config.get(s, {}).get(
                k, kwargs.get('fallback')
            )

    def tearDown(self):
        super().tearDown()
        if self.vault_client:
            self.vault_client.sys.disable_secrets_engine(
                path=self.vault_backend,
            )
            self.vault_client.sys.delete_policy(name=self.vault_policy)
