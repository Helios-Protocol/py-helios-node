=================================
hls JSON RPC Documentation
=================================


This is the documentation for our main RPC module called hls.
In many cases, we share the same calls as Ethereum's eth RPC module, which is described here https://github.com/ethereum/wiki/wiki/JSON-RPC. This is to assist developers and make using Helios Protocol as easy as possible. However, due to our vastly different blockchain architecture, there are many calls that are modified or entirely new.



RPC Functions
-------------

All RPC calls must also include parameters jsonrpc and id. jsonrpc is the version of the rpc, which is currently "2.0", and id should be a unique number for each call you make.

Example:
::

    {"jsonrpc": "2.0", "method": "hls_ping", "params": [], "id":1337}

hls_ping
~~~~~~~~

Returns 'True' if the node RPC is working.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_ping", "params": []}



hls_accounts
~~~~~~~~~~~~

This method has been moved to personal_listAccounts.


hls_blockNumber
~~~~~~~~~~~~~~~

Returns the block number of the newest block on the specified chain.

**Parameters:**

1. Chain address (or wallet address) of the blockchain you would like the block number for.

**RPC Call:**

::

    {"method": "hls_blockNumber", "params": [string]}

**Response:**

The hex encoded block number.

**Example:**

::

    <<
    {"method": "hls_blockNumber", "params": ["0x9c8b20E830c0Db83862892Fc141808eA6a51FEa2"]}
    >>
    "0x5"


hls_gasPrice
~~~~~~~~~~~~

Returns the current minimum gas price in **Gwei**, for this node. Always use a gas price greater than this to ensure your transaction is propagated to the network.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_gasPrice", "params": []}

**Response:**

None

**Example:**

::

    <<
    {"method": "hls_gasPrice", "params": []}
    >>
    "0x1"


hls_getBalance
~~~~~~~~~~~~~~

Returns the balance of the specified account in wei. Optionally you can specify which block to calculate the balance at.

**Parameters:**

1. The hex encoded wallet address.
2. The hex encoded block number at which you want the balance. Set to "latest" for the current balance.

**RPC Call:**

::

    {"method": "hls_getBalance", "params": [string, string]}

**Response:**

Hex encoded balance.

**Example:**

::

    <<
    {"method": "hls_getBalance", "params": ['0x9c8b20E830c0Db83862892Fc141808eA6a51FEa2', '0x1']}
    >>
    "0x845951611c71572012800"


hls_getBalance
~~~~~~~~~~~~~~

Returns the balance of the specified account in wei. Optionally you can specify which block to calculate the balance at.

**Parameters:**

1. The hex encoded wallet address.
2. The hex encoded block number at which you want the balance. Set to "latest" for the current balance.

**RPC Call:**

::

    {"method": "hls_getBalance", "params": [string, string]}

**Response:**

Hex encoded balance.

**Example:**

::

    <<
    {"method": "hls_getBalance", "params": ['0x9c8b20E830c0Db83862892Fc141808eA6a51FEa2', '0x1']}
    >>
    "0x845951611c71572012800"


hls_getBlockTransactionCountByHash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns the number of send and receive transactions in the block matching the provided hash.

**Parameters:**

1. The hex encoded block hash

**RPC Call:**

::

    {"method": "hls_getBlockTransactionCountByHash", "params": [string]}

**Response:**

Hex encoded number of transactions.

**Example:**

::

    <<
    {"method": "hls_getBlockTransactionCountByHash", "params": ['0xab38ba22cd5146a4756a94eb21c11ff3fc8a22f5f46c0dc6d624df3d43f09898']}
    >>
    '0x1'


hls_getBlockTransactionCountByNumber
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns the number of send and receive transactions in the block matching the provided block number and chain address (wallet address).

**Parameters:**

1. The hex encoded block number.
2. The hex encoded chain address.

**RPC Call:**

::

    {"method": "hls_getBlockTransactionCountByNumber", "params": [string, string]}

**Response:**

Hex encoded number of transactions.

**Example:**

::

    <<
    {"method": "hls_getBlockTransactionCountByNumber", "params": ['0x1', '0x9c8b20E830c0Db83862892Fc141808eA6a51FEa2']}
    >>
    '0x1'


hls_getCode
~~~~~~~~~~~

Returns the code saved in the state for the given chain address, or contract address, at the optional block number.

**Parameters:**

1. The hex encoded chain address
2. The hex encoded block number. Use "latest" for the newest block.

**RPC Call:**

::

    {"method": "hls_getCode", "params": [string, string]}

**Response:**

Hex encoded code.

**Example:**

::

    <<
    {"method": "hls_getCode", "params": ['0x81bdf63b9a6e871f560dca1d55e8732b5ccdc2f9', '0x0']}
    >>
    '0x608060405260043610610062576000357c0...



hls_getStorageAt
~~~~~~~~~~~~~~~~

Returns the value from a storage position at a given address.
See https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getstorageat for more details.

**Parameters:**

1. The hex encoded chain address
2. The hex encoded storage location.
3. The hex encoded block number. Use "latest" for the newest block.

**RPC Call:**

::

    {"method": "hls_getStorageAt", "params": [string, string, string]}

**Response:**

Hex encoded storage

**Example:**

::

    <<
    {"method": "hls_getStorageAt", "params": ['0x81bdf63b9a6e871f560dca1d55e8732b5ccdc2f9', '0x0', 'latest']}
    >>
    '0x608060405260043610610062576000357c0...


hls_getTransactionByBlockHashAndIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns information about a transaction by block hash and transaction index position.

**Parameters:**

1. The hex encoded block hash
2. The hex encoded transaction index. Transactions are indexed with send transactions first, then receive transactions next. So if there are 5 send transactions, the first receive transaction will start at index 5.

**RPC Call:**

::

    {"method": "hls_getTransactionByBlockHashAndIndex", "params": [string, string]}

**Response:**

The send or receive transaction.

**Example for a send transaction:**

::

    <<
    {"method": "hls_getTransactionByBlockHashAndIndex", "params": ['0x362fff1fbd4674af637b106e2e09a22e2e70eabc3f082b9a2e25e501a664c2d9', '0x0']}
    >>
    {'nonce': '0x4',
     'gasPrice': '0x77359400',
     'gas': '0x1e8480',
     'to': '0x81bdf63b9a6e871f560dca1d55e8732b5ccdc2f9',
     'value': '0x0',
     'data': '0xce77cb160101010101010101010100000000000000000000000000000000000000000000',
     'v': '0x26',
     'r': '0xa6727d932aee9be095a6fb251e0379096f719efff7e105c91e09374e1e6a336c',
     's': '0x58d3cd6938210fd153d4c0e04cbdce108ec95668fecccf966717324117038fc4',
     'from': '0x9c8b20e830c0db83862892fc141808ea6a51fea2',
     'hash': '0x03a1e51fa1c0bad19cbcdec97677dc94f78a00a463dbafba8f4f62f14e6a4971',
     'gasUsed': '0x0',
     'blockHash': '0xab38ba22cd5146a4756a94eb21c11ff3fc8a22f5f46c0dc6d624df3d43f09898',
     'blockNumber': '0x5',
     'transactionIndex': '0x0',
     'input': '0xce77cb160101010101010101010100000000000000000000000000000000000000000000',
     'isReceive': '0x0'}


**Example for a receive transaction:**

::

    <<
    {"method": "hls_getTransactionByBlockHashAndIndex", "params": ['0x362fff1fbd4674af637b106e2e09a22e2e70eabc3f082b9a2e25e501a664c2d9', '0x0']}
    >>
    {'senderBlockHash': '0xab38ba22cd5146a4756a94eb21c11ff3fc8a22f5f46c0dc6d624df3d43f09898',
     'sendTransactionHash': '0x03a1e51fa1c0bad19cbcdec97677dc94f78a00a463dbafba8f4f62f14e6a4971',
     'isRefund': '0x0',
     'remainingRefund': '0xe096d992e9000',
     'isReceive': '0x1',
     'hash': '0x57275a20ba4ef91b385b93818519b82d0f0b9fcd1b3f3a2ad4ea81942ea1972d',
     'from': '0x9c8b20e830c0db83862892fc141808ea6a51fea2',
     'value': '0x0',
     'gasPrice': '0x77359400',
     'to': '0x81bdf63b9a6e871f560dca1d55e8732b5ccdc2f9',
     'gasUsed': '0x5fac',
     'transactionIndex': '0x0',
     'blockHash': '0x362fff1fbd4674af637b106e2e09a22e2e70eabc3f082b9a2e25e501a664c2d9'}




hls_getTransactionByBlockNumberAndIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns information about a transaction by block number, chain address, and transaction index position.

**Parameters:**

1. The hex encoded block number.
2. The hex encoded transaction index. Transactions are indexed with send transactions first, then receive transactions next. So if there are 5 send transactions, the first receive transaction will start at index 5.
3. The hex encoded chain address.

**RPC Call:**

::

    {"method": "hls_getTransactionByBlockNumberAndIndex", "params": [string, string, string]}

**Response:**

The send or receive transaction.

**Example for a send transaction:**

::

    <<
    {"method": "hls_getTransactionByBlockHashAndIndex", "params": ['0x0', '0x0', '0x81BDF63B9A6E871f560dCA1D55e8732B5cCdC2F9']}
    >>
    {'senderBlockHash': '0x859070d5ea10605de91710367d0822719c84b2e4638fe994915fa7915095bb21',
     'sendTransactionHash': '0x273c9bf63fc7bcb997f3d199578287ceb0043f1d7bd320fcfcc55a73e0d196b4',
     'isRefund': '0x0',
     'remainingRefund': '0x0',
     'isReceive': '0x1',
     'hash': HexBytes('0xc514f01f66664c6ef4c22fb6a77494ffc3682ef636f26f9e4568c2080ef98d47'),
     'from': '0x9c8b20E830c0Db83862892Fc141808eA6a51FEa2',
     'value': 0,
     'gasPrice': 2000000000,
     'to': '0x',
     'gasUsed': '0x0',
     'transactionIndex': 0,
     'blockHash': HexBytes('0xd3ff2b75e71ccb4327c0a7a2384234f2156b3c907f2256a908800674fca1f55f')}



**Example for a receive transaction:**
See hls_getTransactionByBlockHashAndIndex







