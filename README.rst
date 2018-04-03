===========
vaultlocker
===========

Utility to store and retrieve secrets in Hashicorp Vault.

Vault provides a nice way to manage secrets within complex software
deployments.

vaultlocker provides a way to store and retrieve files in Vault,
automatically retrieving files on boot required for the operation
of a system.  These might include encryption key files for dm-crypt.

vaultlocker is configured using `/etc/vaultloker/vaultlocker.conf`::

    [vault]
    url = https://vault.internal:8200
    approle = 4a1b84d2-7bb2-4c07-9804-04d1683ac925
    backend = secret

vaultlocker defaults to using a backend with the name `secret`.

A file can be stored in vaultlocker::

    sudo vaultlocker store /etc/dm-crypt/sdb.key

This will automatically create a new systemd unit which will
retrieve the file on reboot for system operation.

A file can also be retrieved from the command line::

    sudo vaultlocker retrieve f65b9e66-8f0c-4cae-b6f5-6ec85ea134f2

File are written to /run/vaultlocker (typically a tmpfs mount)
and symlinks are created from the original file location::

    /etc/dm-crypt/sdb.key -> /run/vaultlocker/f65b9e66-8f0c-4cae-b6f5-6ec85ea134f2

Authentication to Vault is done using an AppRole without a secret_id; its assumed
that a CIDR based ACL is in use to allow permitted systems within the Data Center
to login and retrieve secrets from Vault.

* Free software: Apache license
* Documentation: https://docs.openstack.org/vaultlocker/latest
* Source: https://git.openstack.org/cgit/openstack/vaultlocker
* Bugs: https://bugs.launchpad.net/vaultlocker

Features
--------

TODO
----

* Execution of provided command post retrieve
* Skip retrieval to filesystem - pipe directly to retrieve
  post-command.
