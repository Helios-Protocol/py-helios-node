=================================
personal JSON RPC Documentation
=================================


This is the documentation for our implementation of Ethereum's geth personal RPC calls.
We have made our personal RPC identical to that of Ethereum's geth personal so that developers have no need
to modify their existing code and can integrate Helios Protocol more easily. You can find the
original Ethereum documentation here: https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal,
which is all valid for our RPC as well. We will also provide some documentation here.

To use the personal RPC on your node, you must start it with the --enable_private_rpc flag.

::

    python ~/py-helios-node/helios/main.py --enable_private_rpc

If you would like to manually add all of your keystore files before starting the node, you can do so
by copying them into the py-helios-node/helios/keystore/ directory. You can use any naming scheme you would like.


RPC Functions
-------------

personal_importRawKey
~~~~~~~~~~~~~~~~~~~~~

**Parameters:**

1. The 32 byte hex encoded private key.
2. The password that will be used to encrypt the account and keystore.

**RPC Call:**

::

    {"method": "personal_importRawKey", "params": [string, string]}

**Response:**

The wallet address of the account. This will be a hex encoded string.

**Example:**

::

    <<
    {"method": "personal_importRawKey", "params": ["0x1232122312132131232131231231231231231231231231221231232131231232", "H4x0r"]}
    >>
    "0xd9107f501d15E07E75D281dCe80C96F09151B657"


personal_listAccounts
~~~~~~~~~~~~~~~~~~~~~

**Parameters:**

None

**RPC Call:**

::

    {"method": "personal_listAccounts", "params": []}

**Response:**

A list of hex addresses that are available from the keystores in the keystore directory.

**Example:**

::

    <<
    {"method": "personal_listAccounts", "params": []}
    >>
    ["0x5e97870f263700f46aa00d967821199b9bc5a120", "0x3d80b31a78c30fc628f20b2c89d7ddbf6e53cedc"]


personal_newAccount
~~~~~~~~~~~~~~~~~~~

**Parameters:**

1. The password that will be used to encrypt the newly generated account and keystore.

**RPC Call:**

::

    {"method": "personal_newAccount", "params": [string]}

**Response:**

The wallet address of the newly generated account. This will be a hex encoded string.

**Example:**

::

    <<
    {"method": "personal_newAccount", "params": ["H4x0r"]}
    >>
    "0x5e97870f263700f46aa00d967821199b9bc5a120"


personal_unlockAccount
~~~~~~~~~~~~~~~~~~~~~~

**Parameters:**

1. The hex encoded wallet address of the account to be unlocked.
2. The password that will be used to encrypt the newly generated account and keystore.
3. The duration that the account will be unlocked. If this is 0, the account is unlocked until the node shuts down.

**RPC Call:**

::

    {"method": "personal_unlockAccount", "params": [string, string, number]}

**Response:**

None

**Example:**

::

    <<
    {"method": "personal_unlockAccount", "params": ['0xd9107f501d15E07E75D281dCe80C96F09151B657', 'test', 5]}
    >>


personal_sign
~~~~~~~~~~~~~

Returns the signature of the signed message. The message is modified to prevent misuse in a way analogous to EIP 191 on Ethereum:
::

    sign(keccack256(b"\x19Helios Signed Message:\n" + str(len(message_bytes)).encode('utf-8') + message.encode("utf-8")))).

If the password is not provided (set as "") then the account must be unlocked. If the password is provided then the account will be unlocked to sign this message.

**Parameters:**


1. The message to be encoded.
2. The wallet address of the account that will sign the message.
3. The password that will be used to encrypt the newly generated account and keystore.


**RPC Call:**

::

    {"method": "personal_sign", "params": [string, string, string]}

**Response:**

Hex encoded signature of the signed message.

**Example:**

::

    <<
    {"method": "personal_sign", "params": ["Hello World", "0xd9107f501d15E07E75D281dCe80C96F09151B657", "test"]}
    >>
    '0xb2278880267630871b87626005500ca5728b96b5e798a2b9ffa0a87ab44e53ef7d9ae6c2a7bd54da55ddbc45faca477c047a72650370b6ad8cdacd85eabbd9931c'

Or without providing a password each time. We first unlock the account for 300 seconds:

::

    <<
    {"method": "personal_unlockAccount", "params": ["'0xd9107f501d15E07E75D281dCe80C96F09151B657'", "test", "300"]}
    <<
    {"method": "personal_sign", "params": ["Hello World", "0xd9107f501d15E07E75D281dCe80C96F09151B657", ""]}
    >>
    '0xb2278880267630871b87626005500ca5728b96b5e798a2b9ffa0a87ab44e53ef7d9ae6c2a7bd54da55ddbc45faca477c047a72650370b6ad8cdacd85eabbd9931c'



personal_ecRecover
~~~~~~~~~~~~~~~~~~

**Parameters:**

1. The message to be encoded.
2. The signature of the signed message as created by personal_sign

**RPC Call:**

::

    {"method": "personal_ecRecover", "params": [message, signature]}

**Response:**

Hex encoded checksum wallet address of the signer

**Example:**

::

    <<
    {"method": "personal_ecRecover", "params": [personal_ecRecover, "0xb2278880267630871b87626005500ca5728b96b5e798a2b9ffa0a87ab44e53ef7d9ae6c2a7bd54da55ddbc45faca477c047a72650370b6ad8cdacd85eabbd9931c"]}
    >>
    "0xd9107f501d15E07E75D281dCe80C96F09151B657"