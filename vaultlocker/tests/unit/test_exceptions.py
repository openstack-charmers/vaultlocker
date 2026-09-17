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

"""Tests for `vaultlocker.exceptions`."""

from vaultlocker import exceptions
from vaultlocker.tests.unit import base


class TestExceptions(base.TestCase):

    def test_base_default_message(self):
        error = exceptions.VaultlockerException()

        self.assertEqual('Empty VaultlockerException', str(error))

    def test_base_uses_first_argument_as_message(self):
        error = exceptions.VaultlockerException('boom')

        self.assertEqual('boom', str(error))

    def test_cluster_identity_mismatch_message(self):
        error = exceptions.ClusterIdentityMismatchError('cluster-a',
                                                        'cluster-b')

        self.assertIn('cluster-a', str(error))
        self.assertIn('cluster-b', str(error))

    def test_managed_key_not_found_message(self):
        error = exceptions.ManagedKeyNotFoundError('mount/host/uuid')

        self.assertIn('mount/host/uuid', str(error))

    def test_luks_failure_message(self):
        error = exceptions.LuksFormatError('/dev/sdb', 'boom')

        self.assertEqual("Can't operate on /dev/sdb. Error: boom", str(error))
