Snap VM functional tests
========================

These tests exercise the real ``vaultlocker`` snap on a virtual machine,
covering behavior that requires a real host:

* after a reboot the device unlocks without the original credential;
* while Vault is unavailable the device stays locked and unlocks once
  Vault returns;
* a snap refresh keeps the enrollment and does not add another managed
  key.

Unlike the other functional tests, these do not mock device operations.
They install the built snap, create a real LUKS device, enroll it, and
reboot the VM to exercise Pebble boot-time unlock.

Prerequisites
-------------

* An LXD virtual machine running Ubuntu 24.04 with a dedicated scratch
  block device that persists across reboots.
* The ``lxc`` client available on the test host.
* A built ``vaultlocker`` snap.

Environment variables
---------------------

``VAULTLOCKER_TEST_VM``
    Name of the LXD VM to use (required).

``VAULTLOCKER_SNAP_PATH``
    Path to the built ``vaultlocker`` ``.snap`` on the test host (required).

``VAULTLOCKER_TEST_DEVICE``
    Persistent block device to use inside the VM (default ``/dev/sdb``).

The tests are skipped when ``VAULTLOCKER_TEST_VM`` or
``VAULTLOCKER_SNAP_PATH`` is unset.

Creating a suitable VM
----------------------

Create a virtual machine with a scratch disk:

::

    lxc launch ubuntu:24.04 vaultlocker-vm --vm
    truncate -s 512M /tmp/vaultlocker-scratch.img
    lxc config device add vaultlocker-vm scratch disk \
        source=/tmp/vaultlocker-scratch.img
    lxc restart vaultlocker-vm

Running
-------

::

    VAULTLOCKER_TEST_VM=vaultlocker-vm \
    VAULTLOCKER_SNAP_PATH=./vaultlocker_0.1_amd64.snap \
    stestr run "^vaultlocker.tests.functional.snap.*"

The tests reinstall the snap and reinitialise a file-backed Vault service
at the start of each run, so they do not depend on the VM's prior state.
The test Vault is stopped at the end of the run.
