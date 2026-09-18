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

"""Errors returned as controlled command failures."""


class VaultlockerException(Exception):
    """Base class for controlled vaultlocker errors."""

    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = "Empty VaultlockerException"

    def __str__(self):
        return self.message


class ConfigurationError(VaultlockerException):
    """The vaultlocker configuration is missing or invalid."""


class VaultWriteError(VaultlockerException):
    """Writing a key to Vault failed."""

    def __init__(self, path, error):
        super().__init__("Can't write to vault at path {}, error: {}".format(
            path, error))


class VaultReadError(VaultlockerException):
    """Reading a key back from Vault failed."""

    def __init__(self, path, error):
        super().__init__("Can't read vault at path {}, error: {}".format(
            path, error))


class VaultKeyMismatch(VaultlockerException):
    """A key read back from Vault does not match what was written."""

    def __init__(self, path):
        super().__init__(
            "Vault key at path {} does not match with generated key".format(
                path))


class VaultConnectionError(VaultlockerException):
    """Vault was unavailable or authentication failed after retries."""

    def __init__(self, error):
        super().__init__("Unable to connect to Vault: {}".format(error))


class ManagedKeyInvalidError(VaultlockerException):
    """The managed key stored in Vault is missing or malformed."""

    def __init__(self, path):
        super().__init__(
            "Vault secret at {} does not contain dmcrypt_key".format(path)
        )


class ManagedKeyNotFoundError(VaultlockerException):
    """No Vault key exists at the expected path."""

    def __init__(self, path):
        super().__init__(
            'No vaultlocker-managed key found at {}'.format(path)
        )


class ExistingKeyInvalidError(VaultlockerException):
    """Existing LUKS credential is missing, unreadable, or wrong."""


class LUKSFailure(VaultlockerException):
    """Base class for all cryptsetup/LUKS-related errors."""

    def __init__(self, block_device, error):
        super().__init__("Can't operate on {}. Error: {}".format(
            block_device, error))


class LuksValidationError(LUKSFailure):
    """The device's LUKS state could not be verified."""


class LuksFormatError(LUKSFailure):
    """Formatting a LUKS device failed."""


class LuksAddKeyError(LUKSFailure):
    """Adding a LUKS key failed."""


class MapperOpenError(LUKSFailure):
    """Opening the dm-crypt mapper failed."""


class BootConfigError(LUKSFailure):
    """Registering the boot-time unlock mechanism failed."""
