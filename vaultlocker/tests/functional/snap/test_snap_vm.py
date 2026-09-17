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

"""Snap functional tests for encrypted-storage reboot and refresh.

These tests cover behavior that requires a real host:

* after a reboot the device unlocks without the original credential;
* while Vault is unavailable the device stays locked and unlocks once
  Vault returns;
* a snap refresh keeps the enrollment and does not add another managed
  key.

The test class provisions a file-backed Vault service and the built
``vaultlocker`` snap on the target VM, then reboots the VM as needed.
"""

from vaultlocker.tests.functional.snap import base


class SnapRebootRefreshTest(base.SnapVMFunctionalTest):
    """Reboot, Vault-unavailability and refresh behaviour of the snap."""

    def test_snap_refresh_preserves_enrollment(self):
        """A snap refresh keeps the managed key and does not add a key."""
        keyslots_before = self._keyslot_count()
        layers_before = sorted(self._layer_files())

        # Operator passphrase plus one Vaultlocker-managed key.
        self.assertEqual(2, keyslots_before)
        self.assertTrue(self._original_passphrase_unlocks())
        self.assertTrue(layers_before)

        # Reinstall the snap from the same file: this refreshes to a new
        # revision and must preserve SNAP_COMMON.
        self._exec(
            "snap install --dangerous {}".format(base.SNAP_REMOTE_PATH)
        )

        self.assertEqual(layers_before, sorted(self._layer_files()))
        self.assertEqual(keyslots_before, self._keyslot_count())
        self.assertTrue(self._original_passphrase_unlocks())

        # The boot-time unlock service is still scheduled after the refresh.
        self._close_mapper()
        self._exec("systemctl restart snap.vaultlocker.pebble.service")
        self.assertTrue(
            self._wait_for_mapper(True),
            "mapper was not restored after a snap refresh",
        )

    def test_reboot_unlock_without_credentials(self):
        """After a reboot the device unlocks without the original secret."""
        self._close_mapper()
        self.assertFalse(self._mapper_exists())

        self._reboot_vm()
        # The test Vault starts sealed after a reboot. Unseal it and wait
        # for Vaultlocker to restore the mapper, without running the CLI.
        self._unseal_vault()

        self.assertTrue(
            self._wait_for_mapper(True),
            "mapper was not restored after reboot",
        )

    def test_vault_unavailable_at_boot(self):
        """Storage stays locked while Vault is unavailable, then unlocks."""
        self._close_mapper()
        self.assertFalse(self._mapper_exists())

        self._reboot_vm()
        # Vault is sealed, so the device must remain locked.
        self.assertFalse(
            self._wait_for_mapper(True, timeout=30),
            "mapper should not appear while Vault is unavailable",
        )

        self._unseal_vault()
        self.assertTrue(
            self._wait_for_mapper(True),
            "mapper was not restored after Vault returned",
        )
