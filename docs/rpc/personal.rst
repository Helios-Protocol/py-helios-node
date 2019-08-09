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

All RPC calls must also include parameters jsonrpc and id. jsonrpc is the version of the rpc, which is currently "2.0", and id should be a unique number for each call you make.

Example:
::

    {"jsonrpc": "2.0", "method": "personal_listAccounts", "params": [], "id":1337}

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


personal_sendTransaction
~~~~~~~~~~~~~~~~~~~~~~~~

Creates and signs the transaction, adds it to a block, and sends it to the blockchain. Unlike Ethereum, since each person is in charge of their own blockchain, there are no transaction queues. This means you have to wait the minimum time between blocks (currently 10 seconds) each time you use this function. If you would like to send many transactions at once, use personal_sendTransactions instead.

**Parameters:**

1. The transaction dictionary with the format:
::

    tx = {'from': hex encoded from address,
          'to': hex encoded to address,
          'value': hex encoded transaction amount,
          'gas': hex encoded maximum gas (optional, defaults to min allowed gas),
          'gasPrice': hex encoded gas price (in wei) (optional, defaults to 21,000),
          'data': hex encoded data (optional, defaults to b''),
          'nonce': hex encoded transaction nonce (optional)}.

2. The password to unlock the account to send the transaction. If this is left blank (as ""), then the transaction will only send if the account is already unlocked.


**RPC Call:**

::

    {"method": "personal_sendTransaction", "params": [tx, string]}

**Response:**

The hash of the transaction

**Example:**

::

    <<
    {"method": "personal_sendTransaction", "params": [{'from': '0x0D1630cb77c00D95F7FA32bCcfe80043639681Be', 'to': '0xd9107f501d15E07E75D281dCe80C96F09151B657', 'value': 10000000000000000}, 'test_password']}
    >>
    '0x58d825d4bfe9810cbe546e46c94edf4b41e7b3256d74bf694d946f92124d34b5'

personal_sendTransactions
~~~~~~~~~~~~~~~~~~~~~~~~~

Identical to personal_sendTransaction, except it takes multiple transactions and adds them all to the same block, and it will automatically receive any pending transactions. This can be used to send many transactions at the same time, up to the max gas of the block. Since these are all going into the same block, they must all be from the same address. If you want to send multiple transactions from different addresses, just call this function once for each address. The minimum time between blocks is for each individual wallet address, but multiple addresses can import blocks in parallel.

**Parameters:**

1. A list of transaction dictionaries as described in personal_sendTransaction. All transactions must be from the same account:

2. The password to unlock the account to send the transaction. If this is left blank (as ""), then the transaction will only send if the account is already unlocked.


**RPC Call:**

::

    {"method": "personal_sendTransactions", "params": [[tx1,tx2,tx3...], string]}

**Response:**

A list of the send and receive transaction hashes

**Example:**

::

    <<
    {"method": "personal_sendTransactions", "params": [[{'from': '0x0D1630cb77c00D95F7FA32bCcfe80043639681Be', 'to': '0xd9107f501d15E07E75D281dCe80C96F09151B657', 'value': 10000000000000000},{'from': '0x0D1630cb77c00D95F7FA32bCcfe80043639681Be', 'to': '0xd9107f501d15E07E75D281dCe80C96F09151B657', 'value': 10000000000000000}], 'test_password']}
    >>
    ['0xd98d1d628ea4c93dee20a8b1e691acbb45b3b9aa6997baa1a0006a5f4c86efbb',
    '0x297e7a7443926d6bbc202d81bff3081a9a53caaf64cc5685760aaca439ce1b50']


personal_receiveTransactions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creates and signs a block with all available receive transactions, then sends it to the network. Will raise an exception if there are no receivable transactions.

**Parameters:**

1. Hex encoded wallet address.

2. The password to unlock the account to send the transaction. If this is left blank (as ""), then the transaction will only send if the account is already unlocked.


**RPC Call:**

::

    {"method": "personal_receiveTransactions", "params": [string, string]}

**Response:**

A list of hashes of any receive transactions that were added to the block.


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


personal_getAccountsWithReceivableTransactions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fetches wallet addresses of all saved accounts that have pending receive transactions. Same as hls_filterAddressesWithReceivableTransactions except it only looks at saved accounts.

**Parameters:**

None

**RPC Call:**

::

    {"method": "personal_getAccountsWithReceivableTransactions", "params": []}

**Response:**

Returns a list of addresses with receivable transactions.

**Example:**

::

    <<
    {"method": "personal_getAccountsWithReceivableTransactions", "params":[]}
    >>
    ['0x0d1630cb77c00d95f7fa32bccfe80043639681be', '0x9c8b20e830c0db83862892fc141808ea6a51fea2']