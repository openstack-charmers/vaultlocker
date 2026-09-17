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

"""Base class for vaultlocker snap functional tests.

These tests exercise the real snap on a virtual machine, including
dm-crypt, Pebble boot-time unlock and Vault availability. They are skipped
unless ``VAULTLOCKER_SNAP_PATH`` and ``VAULTLOCKER_TEST_VM`` are set and the
``lxc`` client is available.

Prerequisites:

* An LXD virtual machine (Ubuntu 24.04) named by ``VAULTLOCKER_TEST_VM``
  with a dedicated scratch block device named by
  ``VAULTLOCKER_TEST_DEVICE`` (default ``/dev/sdb``). The device must persist
  across reboots.
* ``VAULTLOCKER_SNAP_PATH`` pointing at a built ``vaultlocker`` ``.snap``.

Provisioning is idempotent: the snap is reinstalled and the test Vault is
reinitialised at the start of each test class, so a run does not depend on
the VM's prior state.
"""

import json
import os
import shutil
import subprocess
import time
import unittest

VM_ENV = "VAULTLOCKER_TEST_VM"
SNAP_PATH_ENV = "VAULTLOCKER_SNAP_PATH"
DEVICE_ENV = "VAULTLOCKER_TEST_DEVICE"

INTERFACES = [
    "dm-crypt",
    "block-devices",
]

SNAP_REMOTE_PATH = "/root/vaultlocker.snap"
VAULT_COMMON = "/var/snap/vault/common"
VAULT_ADDR = "http://127.0.0.1:8200"
VAULTLOCKER_COMMON = "/var/snap/vaultlocker/common"
VAULTLOCKER_CONF = "{}/vaultlocker.conf".format(VAULTLOCKER_COMMON)
PASSPHRASE = "operatorpass"
PASSPHRASE_FILE = "{}/passphrase".format(VAULTLOCKER_COMMON)

BOOT_TIMEOUT = 240
MAPPER_TIMEOUT = 180
POLL_INTERVAL = 3

VAULT_HCL = """storage "file" {{ path = "{common}/data" }}
listener "tcp" {{
  address     = "127.0.0.1:8200"
  tls_disable = true
}}
disable_mlock = true
""".format(common=VAULT_COMMON)

VAULT_UNIT = """[Unit]
Description=Vault test server (file storage)
After=network-online.target

[Service]
ExecStart=/snap/bin/vault server -config={common}/vault.hcl
Restart=on-failure

[Install]
WantedBy=multi-user.target
""".format(common=VAULT_COMMON)

VAULT_SETUP_SCRIPT = """#!/bin/bash
set -euo pipefail
export VAULT_ADDR={addr}
vault operator init -key-shares=1 -key-threshold=1 -format=json \
    > {common}/init.json
python3 - <<'PY'
import json
data = json.load(open("{common}/init.json"))
open("{common}/unseal-key", "w").write(data["unseal_keys_b64"][0])
open("{common}/root-token", "w").write(data["root_token"])
PY
vault operator unseal "$(cat {common}/unseal-key)" >/dev/null
export VAULT_TOKEN="$(cat {common}/root-token)"
vault secrets enable -path=vaultlocker kv-v2
vault auth enable approle
cat > {common}/policy.hcl <<'POLICY'
path "vaultlocker/data/*" {{
  capabilities = ["create", "read", "update", "delete"]
}}
path "vaultlocker/metadata/*" {{
  capabilities = ["read", "delete", "list"]
}}
POLICY
vault policy write vaultlocker {common}/policy.hcl >/dev/null
vault write auth/approle/role/vaultlocker token_policies=vaultlocker \
    token_ttl=1h token_max_ttl=4h secret_id_ttl=0 >/dev/null
""".format(addr=VAULT_ADDR, common=VAULT_COMMON)

VAULT_ROLE_ID_SCRIPT = """#!/bin/bash
set -euo pipefail
export VAULT_ADDR={addr}
export VAULT_TOKEN="$(cat {common}/root-token)"
vault read -format=json auth/approle/role/vaultlocker/role-id
""".format(addr=VAULT_ADDR, common=VAULT_COMMON)

VAULT_SECRET_ID_SCRIPT = """#!/bin/bash
set -euo pipefail
export VAULT_ADDR={addr}
export VAULT_TOKEN="$(cat {common}/root-token)"
vault write -f -format=json auth/approle/role/vaultlocker/secret-id
""".format(addr=VAULT_ADDR, common=VAULT_COMMON)


def snap_tests_enabled():
    """Return True when the snap VM functional tests can run."""
    return all([
        os.environ.get(VM_ENV),
        os.environ.get(SNAP_PATH_ENV),
        shutil.which("lxc"),
    ])


@unittest.skipUnless(
    snap_tests_enabled(),
    "Set {} and {} (and install lxc) to run snap VM tests".format(
        VM_ENV, SNAP_PATH_ENV
    ),
)
class SnapVMFunctionalTest(unittest.TestCase):
    """Base class provisioning the snap and Vault on a VM."""

    vm = None
    snap_path = None
    device = None

    @classmethod
    def setUpClass(cls):
        """Provision the VM, snap and Vault, then enroll the device."""
        cls.vm = os.environ[VM_ENV]
        cls.snap_path = os.environ[SNAP_PATH_ENV]
        cls.device = os.environ.get(DEVICE_ENV, "/dev/sdb")

        cls._start_vm()
        cls._install_snap()
        cls._connect_interfaces()
        cls._write_passphrase_file()
        cls._setup_vault()
        cls._write_vaultlocker_config()
        cls._prepare_luks_device()
        cls._enroll_device()

    @classmethod
    def tearDownClass(cls):
        """Stop the test Vault service."""
        cls._exec("systemctl stop vault-test.service || true", check=False)

    # -- VM helpers ------------------------------------------------------

    @classmethod
    def _lxc(cls, *args, check=True):
        """Run a local lxc command."""
        return subprocess.run(
            ["lxc"] + list(args),
            check=check,
            capture_output=True,
            text=True,
        )

    @classmethod
    def _exec(cls, command, check=True, timeout=600):
        """Run a shell command inside the VM."""
        return subprocess.run(
            ["lxc", "exec", cls.vm, "--", "bash", "-lc", command],
            check=check,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    @classmethod
    def _push(cls, local_path, remote_path):
        """Copy a local file into the VM."""
        cls._lxc(
            "file",
            "push",
            str(local_path),
            "{}{}".format(cls.vm, remote_path),
        )

    @classmethod
    def _write_remote(cls, path, content):
        """Write content to a file inside the VM."""
        subprocess.run(
            ["lxc", "exec", cls.vm, "--", "tee", path],
            check=True,
            capture_output=True,
            text=True,
            input=content,
        )

    @classmethod
    def _run_script(cls, name, content, check=True):
        """Write and run a script inside the VM."""
        path = "/root/{}.sh".format(name)
        cls._write_remote(path, content)
        return cls._exec("bash {}".format(path), check=check)

    @classmethod
    def _start_vm(cls):
        """Start the VM if needed and wait until it is reachable."""
        cls._lxc("start", cls.vm, check=False)
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            if cls._exec("true", check=False).returncode == 0:
                return
            time.sleep(POLL_INTERVAL)
        raise RuntimeError("VM {} did not become ready".format(cls.vm))

    @classmethod
    def _reboot_vm(cls):
        """Restart the VM and wait until the test Vault is reachable."""
        cls._lxc("restart", cls.vm)
        cls._start_vm()
        cls._wait_for_vault()

    # -- Provisioning ----------------------------------------------------

    @classmethod
    def _install_snap(cls):
        """Install the built snap and clear any previous state."""
        cls._push(cls.snap_path, SNAP_REMOTE_PATH)
        cls._exec("snap remove vaultlocker >/dev/null 2>&1 || true")
        cls._exec("rm -rf {}/* || true".format(VAULTLOCKER_COMMON))
        cls._exec(
            "snap install --dangerous --jailmode {}".format(SNAP_REMOTE_PATH)
        )

    @classmethod
    def _connect_interfaces(cls):
        """Connect the snap interfaces required for dm-crypt."""
        for iface in INTERFACES:
            cls._exec(
                "snap connect vaultlocker:{} || true".format(iface),
                check=False,
            )

    @classmethod
    def _write_passphrase_file(cls):
        """Write the operator LUKS passphrase for enrollment."""
        cls._exec("mkdir -p {}".format(VAULTLOCKER_COMMON))
        cls._exec(
            "printf %s {} > {}".format(PASSPHRASE, PASSPHRASE_FILE)
        )

    @classmethod
    def _setup_vault(cls):
        """Install, initialise and configure a file-backed Vault service."""
        cls._exec("snap install vault || true", check=False)
        cls._exec("mkdir -p {}/data".format(VAULT_COMMON))
        cls._write_remote(
            "{}/vault.hcl".format(VAULT_COMMON), VAULT_HCL
        )
        cls._write_remote(
            "/etc/systemd/system/vault-test.service", VAULT_UNIT
        )
        cls._exec(
            "systemctl stop vault-test.service || true", check=False
        )
        cls._exec("rm -rf {}/data/* || true".format(VAULT_COMMON))
        cls._exec("systemctl daemon-reload")
        cls._exec("systemctl enable --now vault-test.service")
        cls._wait_for_vault()
        cls._run_script("vault-setup", VAULT_SETUP_SCRIPT)

    @classmethod
    def _wait_for_vault(cls):
        """Wait until the Vault HTTP endpoint responds."""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = cls._exec(
                "curl -s -o /dev/null -w '%{{http_code}}' {}".format(
                    VAULT_ADDR
                ),
                check=False,
            )
            code = result.stdout.strip()
            if code and code != "000":
                return
            time.sleep(POLL_INTERVAL)
        raise RuntimeError("Vault did not start")

    @classmethod
    def _unseal_vault(cls):
        """Unseal the test Vault."""
        cls._exec(
            "export VAULT_ADDR={}; vault operator unseal "
            "$(cat {}/unseal-key)".format(VAULT_ADDR, VAULT_COMMON)
        )

    @classmethod
    def _write_vaultlocker_config(cls):
        """Write the vaultlocker config using a fresh AppRole."""
        role_out = cls._run_script("vault-role-id", VAULT_ROLE_ID_SCRIPT)
        role_id = json.loads(role_out.stdout)["data"]["role_id"]
        secret_out = cls._run_script(
            "vault-secret-id", VAULT_SECRET_ID_SCRIPT
        )
        secret_id = json.loads(secret_out.stdout)["data"]["secret_id"]
        config = (
            "[vault]\n"
            "url = {url}\n"
            "approle = {role}\n"
            "secret_id = {secret}\n"
            "backend = vaultlocker\n"
            "kv_version = 2\n"
        ).format(url=VAULT_ADDR, role=role_id, secret=secret_id)
        cls._write_remote(VAULTLOCKER_CONF, config)

    @classmethod
    def _prepare_luks_device(cls):
        """Create a fresh LUKS container with the operator passphrase."""
        cls._exec(
            "for m in $(dmsetup ls --target crypt 2>/dev/null "
            "| awk '{print $1}'); do cryptsetup close \"$m\" || true; "
            "done",
            check=False,
        )
        cls._exec("wipefs -a {} || true".format(cls.device), check=False)
        cls._exec(
            "dd if=/dev/zero of={} bs=1M count=16 status=none".format(
                cls.device
            )
        )
        cls._exec(
            "cryptsetup --batch-mode --key-file {} luksFormat {}".format(
                PASSPHRASE_FILE, cls.device
            )
        )

    @classmethod
    def _enroll_device(cls):
        """Enroll the device with a Vault-managed key."""
        cls._exec(
            "snap run vaultlocker --config {} enroll "
            "--existing-key-file {} {}".format(
                VAULTLOCKER_CONF, PASSPHRASE_FILE, cls.device
            )
        )

    # -- Queries ---------------------------------------------------------

    @classmethod
    def _luks_uuid(cls):
        """Return the LUKS UUID of the test device."""
        result = cls._exec("cryptsetup luksUUID {}".format(cls.device))
        return result.stdout.strip()

    @classmethod
    def _mapper_path(cls):
        """Return the mapper path for the test device."""
        return "/dev/mapper/crypt-{}".format(cls._luks_uuid())

    @classmethod
    def _mapper_exists(cls):
        """Return True when the mapper device exists."""
        result = cls._exec(
            "test -e {}".format(cls._mapper_path()), check=False
        )
        return result.returncode == 0

    @classmethod
    def _wait_for_mapper(cls, present, timeout=MAPPER_TIMEOUT):
        """Wait up to timeout for the mapper to reach the desired state."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cls._mapper_exists() == present:
                return True
            time.sleep(POLL_INTERVAL)
        return False

    @classmethod
    def _keyslot_count(cls):
        """Return the number of LUKS keyslots in use."""
        result = cls._exec("cryptsetup luksDump {}".format(cls.device))
        count = 0
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped[:2].rstrip(":").isdigit() and ": luks2" in stripped:
                count += 1
        return count

    @classmethod
    def _layer_files(cls):
        """Return the persistent Pebble layer files for the device."""
        result = cls._exec(
            "ls {}/pebble/layers/ 2>/dev/null || true".format(
                VAULTLOCKER_COMMON
            )
        )
        return [
            name for name in result.stdout.split() if name.endswith(".yaml")
        ]

    @classmethod
    def _original_passphrase_unlocks(cls):
        """Return True when the operator passphrase still unlocks it."""
        result = cls._exec(
            "cryptsetup --batch-mode --key-file {} "
            "open --test-passphrase {}".format(
                PASSPHRASE_FILE, cls.device
            ),
            check=False,
        )
        return result.returncode == 0

    @classmethod
    def _close_mapper(cls):
        """Close the mapper device if it is open."""
        cls._exec(
            "cryptsetup close crypt-{} || true".format(cls._luks_uuid()),
            check=False,
        )
