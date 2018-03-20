2. Edit the ``/etc/vaultlocker/vaultlocker.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://vaultlocker:VAULTLOCKER_DBPASS@controller/vaultlocker
