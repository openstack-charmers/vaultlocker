Prerequisites
-------------

Before you install and configure the vaultlocker service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``vaultlocker`` database:

     .. code-block:: none

        CREATE DATABASE vaultlocker;

   * Grant proper access to the ``vaultlocker`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON vaultlocker.* TO 'vaultlocker'@'localhost' \
          IDENTIFIED BY 'VAULTLOCKER_DBPASS';
        GRANT ALL PRIVILEGES ON vaultlocker.* TO 'vaultlocker'@'%' \
          IDENTIFIED BY 'VAULTLOCKER_DBPASS';

     Replace ``VAULTLOCKER_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``vaultlocker`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt vaultlocker

   * Add the ``admin`` role to the ``vaultlocker`` user:

     .. code-block:: console

        $ openstack role add --project service --user vaultlocker admin

   * Create the vaultlocker service entities:

     .. code-block:: console

        $ openstack service create --name vaultlocker --description "vaultlocker" vaultlocker

#. Create the vaultlocker service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        vaultlocker public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        vaultlocker internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        vaultlocker admin http://controller:XXXX/vY/%\(tenant_id\)s
