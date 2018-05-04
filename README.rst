===========
vaultlocker
===========

.. image:: https://travis-ci.org/openstack-charmers/vaultlocker.svg?branch=master
    :target: https://travis-ci.org/openstack-charmers/vaultlocker

Utility to store and retrieve dm-crypt keys in Hashicorp Vault.

Vault provides a nice way to manage secrets within complex software
deployments.

vaultlocker provides a way to store and retrieve dm-crypt encryption
keys in Vault, automatically retrieving keys and opening LUKS dm-crypt
devices on boot.

vaultlocker is configured using `/etc/vaultlocker/vaultlocker.conf`::

    [vault]
    url = https://vault.internal:8200
    approle = 4a1b84d2-7bb2-4c07-9804-04d1683ac925
    backend = secret

vaultlocker defaults to using a backend with the name `secret`.

A block device can be encrypted and its key stored in vault::

    sudo vaultlocker encrypt /dev/sdd1

This will automatically create a new systemd unit which will
automatically retrieve the key and open the LUKS/dm-crypt device
on boot.

Unless a UUID is provided (using the optional --uuid flag)
vaultlocker will generate a UUID to label and identify the block
device during subsequent operations.

A block device can also be opened from the command line using its
UUID (hint - the block device or partition will be labelled with the
UUID)::

    sudo vaultlocker decrypt f65b9e66-8f0c-4cae-b6f5-6ec85ea134f2

Authentication to Vault is done using an AppRole with a secret_id; its assumed
that a CIDR based ACL is in use to only allow permitted systems within the
Data Center to login and retrieve secrets from Vault.

* Free software: Apache license
* Documentation: https://docs.openstack.org/vaultlocker/latest
* Source: https://git.openstack.org/cgit/openstack/vaultlocker
* Bugs: https://bugs.launchpad.net/vaultlocker
