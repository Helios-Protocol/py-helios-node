=================================
admin JSON RPC Documentation
=================================


The admin module is used for managing the node. Everything is password protected. To enable it, start the node with the --enable-admin-rpc flag.

::

    $ python main.py --enable-admin-rpc flag

Before you can use the admin module, you must first set a password. You can do this by starting the node with the flag set-admin-rpc-password.

::

    $ python main.py set-admin-rpc-password


Passwords are hashed using a slow function to prevent brute force attacks. But make sure your password is as secure as possible.


RPC Functions
-------------
All RPC calls must also include parameters jsonrpc and id. jsonrpc is the version of the rpc, which is currently "2.0", and id should be a unique number for each call you make.

Example:
::

    {"jsonrpc": "2.0", "method": "hls_ping", "params": [], "id":1337}

admin_stopRPC
~~~~~~~~~~~~~

Stops the RPC

**Parameters:**

1) The admin rpc password

**RPC Call:**

::

    {"method": "admin_stopRPC", "params": ['my_awesome_password']}


admin_startRPC
~~~~~~~~~~~~~~

Starts the RPC

**Parameters:**

1) The admin rpc password

**RPC Call:**

::

    {"method": "admin_startRPC", "params": ['my_awesome_password']}