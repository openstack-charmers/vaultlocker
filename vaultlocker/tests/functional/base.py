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
import mock
import os
import uuid

from oslotest import base
from testtools import testcase


TEST_POLICY = '''
path "{backend}/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
'''


class VaultlockerFuncBaseTestCase(base.BaseTestCase):

    """Test case base class for all functional tests."""

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
            raise testcase.TestSkipped('Vault not running')

        self.vault_client = hvac.Client(url=self.vault_addr,
                                        token=self.root_token)

        self.vault_client.enable_secret_backend(
            backend_type='kv',
            description='vault test backend',
            mount_point=self.vault_backend
        )

        try:
            self.vault_client.enable_auth_backend('approle')
        except hvac.exceptions.InvalidRequest:
            pass

        self.vault_client.set_policy(
            name=self.vault_policy,
            rules=TEST_POLICY.format(backend=self.vault_backend)
        )

        self.vault_client.create_role(
            self.vault_approle,
            token_ttl='60s',
            token_max_ttl='60s',
            policies=[self.vault_policy],
            bind_secret_id='true',
            bound_cidr_list='127.0.0.1/32')
        self.approle_uuid = self.vault_client.get_role_id(self.vault_approle)
        self.secret_id = self.vault_client.write(
            'auth/approle/role/{}/secret-id'.format(self.vault_approle)
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
            lambda s, k: self.test_config.get(s).get(k)

    def tearDown(self):
        super(VaultlockerFuncBaseTestCase, self).tearDown()
        if self.vault_client:
            self.vault_client.disable_secret_backend(self.vault_backend)
            self.vault_client.delete_policy(self.vault_policy)
