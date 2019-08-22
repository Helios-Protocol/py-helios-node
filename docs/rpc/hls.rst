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


hls_call
~~~~~~~~

Executes a new message call immediately without creating a transaction on the block chain.

**Parameters:**

1. Object - The transaction call object
::

    from: DATA, 20 Bytes - The address the transaction is sent from.
    to: DATA, 20 Bytes - The address the transaction is directed to.
    gas: QUANTITY - (optional) Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions.
    gasPrice: QUANTITY - (optional) Integer of the gasPrice used for each paid gas
    value: QUANTITY - (optional) Integer of the value sent with this transaction
    data: DATA - (optional) Hash of the method signature and encoded parameters. For details see Ethereum Contract ABI

2. The block at which the call should be made. This is a block on the chain corresponding to the "from" key in parameter 1. This defaults to "latest"

**RPC Call:**

::

    {"method": "hls_call", "params": [object, string]}

**Response:**

The hex encoded result of the computation

**Example:**

::

    <<
    {"method": "hls_call", "params": [{see above}]}
    >>
    "0x5"


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


hls_gasPrice or hls_getGasPrice
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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



hls_getTransactionByHash
~~~~~~~~~~~~~~~~~~~~~~~~

Returns the information about a transaction requested by transaction hash.

**Parameters:**

1. Hex encoded transaction hash

**RPC Call:**

::

    {"method": "hls_getTransactionByHash", "params": [string]}

**Response:**

Returns the send or receive transaction

**Example for a send transaction:**

::

    <<
    {"method": "hls_getTransactionByHash", "params": ['0x6bc56e50ad6776793be1c2b001d1798404f58e1c794bd013d5288e62226a68bf']}
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


hls_getReceivableTransactions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns a list of transactions that are sent to the chain address, but have not yet been received.

**Parameters:**

1. Hex encoded chain address.

**RPC Call:**

::

    {"method": "hls_getReceivableTransactions", "params": [string]}

**Response:**

Returns a list of receivable transactions

**Example:**

::

    <<
    {"method": "hls_getTransactionByHash", "params": ['0x6bc56e50ad6776793be1c2b001d1798404f58e1c794bd013d5288e62226a68bf']}
    >>
    [{'senderBlockHash': '0x1c60210ac93060c2ea586186002d7690a05e49d43b30906818ac670c40bfd72e',
      'sendTransactionHash': '0x1493f924fc32ed4af7a2c06023f19f071e3d8336d513883355e25c4ce6295693',
      'isRefund': '0x0',
      'remainingRefund': '0x0',
      'isReceive': '0x1',
      'hash': '0x4b5c8ab08029e29606a6dbdeab2f0f601f44acacc7ec322b8b2a13cb80317d21',
      'from': '0x9c8b20e830c0db83862892fc141808ea6a51fea2',
      'value': '0x1bc16d674ec80000',
      'gasPrice': '0xb2d05e00',
      'to': '0x0d1630cb77c00d95f7fa32bccfe80043639681be',
      'gasUsed': '0x0'},
     {'senderBlockHash': '0xf58bf29eae9e1303f6d34a5faeb5961de141294a3ff2370e6dd9a431ad3cc19e',
      'sendTransactionHash': '0xae80fe044de77de5fdcf8f96bc800eb380e176b23d216d8f03da571217ede266',
      'isRefund': '0x0',
      'remainingRefund': '0x0',
      'isReceive': '0x1',
      'hash': '0x674dd811058ecb08ed396c43d5e4a8799c9be64aabafc011afdc00b1ef414b37',
      'from': '0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e',
      'value': '0x6f05b59d3b20000',
      'gasPrice': '0xb2d05e00',
      'to': '0x0d1630cb77c00d95f7fa32bccfe80043639681be',
      'gasUsed': '0x0'}]


hls_filterAddressesWithReceivableTransactions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Takes a list of chain addresses (wallet addresses or smart contract addresses), and filters them and returns only the ones that have pending receive transactions. This function can take a significant amount of time if there are a huge number of addresses to check.

**Parameters:**

1. List of hex encoded chain addresses.
2. A hex encoded timestamp. Only look for receivable transactions past this timestamp. Set to 0 to return all receivable transactions. This function will return much more quickly if it only has to check a small time window. For example, if this timestamp is set to 10 minues ago, it will return much more quickly then if it was set to 0.

**RPC Call:**

::

    {"method": "hls_filterAddressesWithReceivableTransactions", "params": [[list of strings], string]}

**Response:**

Returns a list of addresses with receivable transactions

**Example:**

::

    <<
    {"method": "hls_filterAddressesWithReceivableTransactions", "params": [['0x6c11508dA9957c747242EcAd6cf5f93162203D6A', '0x7cB6Ff697d0f7aC22A3CB8056314F5F1a72CC15e', '0x0D1630cb77c00D95F7FA32bCcfe80043639681Be', '0x3C91902221adAa1f94F5451272aA72E869F4565a', '0xD91Edc2384491C5d16c939A011D28cEC11d77851', '0x9c8b20E830c0Db83862892Fc141808eA6a51FEa2'], '0x0']}
    >>
    ['0x0d1630cb77c00d95f7fa32bccfe80043639681be', '0x9c8b20e830c0db83862892fc141808ea6a51fea2']



hls_getReceiveTransactionOfSendTransaction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns the receive transaction corresponding to a given send transaction. If the send transaction hasn't been received then it will raise an error.

**Parameters:**

1. Hex encoded transaction hash of the send transaction

**RPC Call:**

::

    {"method": "hls_getReceiveTransactionOfSendTransaction", "params": [string]}

**Response:**

Returns a receive transaction.

**Example:**

::

    <<
    {"method": "hls_getReceiveTransactionOfSendTransaction", "params": ['0x6bc56e50ad6776793be1c2b001d1798404f58e1c794bd013d5288e62226a68bf']}
    >>
    {'senderBlockHash': '0xf3127dfe113266eedc2717f7d43bc3808954db3d5e187a079da6f358367275a5',
     'sendTransactionHash': '0x6bc56e50ad6776793be1c2b001d1798404f58e1c794bd013d5288e62226a68bf',
     'isRefund': '0x0',
     'remainingRefund': '0x0',
     'isReceive': '0x1',
     'hash': '0x9a5a6cf2c8b43319500609a93fbe14f929a44151325c9da74b38e706870e176c',
     'from': '0x9c8b20e830c0db83862892fc141808ea6a51fea2',
     'value': '0xde0b6b3a7640000',
     'gasPrice': '0xb2d05e00',
     'to': '0x0d1630cb77c00d95f7fa32bccfe80043639681be',
     'gasUsed': '0x0',
     'transactionIndex': '0x1',
     'blockHash': '0x0506ebe2b69cd5619f926a8f1590347f3f78d04007ef6b477b954d53c9061995'}







hls_getTransactionReceipt
~~~~~~~~~~~~~~~~~~~~~~~~~

Returns the receipt of a transaction by transaction hash.

**Parameters:**

1. The hex encoded transaction hash

**RPC Call:**

::

    {"method": "hls_getTransactionReceipt", "params": [string]}

**Response:**

The hex encoded number of transactions.

**Example:**

::

    <<
    {"method": "hls_getTransactionReceipt", "params": ['0x6bc56e50ad6776793be1c2b001d1798404f58e1c794bd013d5288e62226a68bf']}
    >>
    {'statusCode': '0x01',
     'gasUsed': '0x5208',
     'bloom': '0x0',
     'logs': [],
     'blockHash': '0xf3127dfe113266eedc2717f7d43bc3808954db3d5e187a079da6f358367275a5',
     'transactionHash': '0x6bc56e50ad6776793be1c2b001d1798404f58e1c794bd013d5288e62226a68bf',
     'isReceive': '0x0',
     'transactionIndex': '0x0',
     'blockNumber': '0x1',
     'to': '0x0d1630cb77c00d95f7fa32bccfe80043639681be',
     'sender': '0x9c8b20e830c0db83862892fc141808ea6a51fea2',
     'cumulativeGasUsed': '0x5208'}




hls_getTransactionCount
~~~~~~~~~~~~~~~~~~~~~~~

Returns the number of transactions sent from an address as calculated at the specificed block number.

**Parameters:**

1. The hex encoded chain address.
2. The hex encoded block number. Defaults to "latest" to return the current transaction count.

**RPC Call:**

::

    {"method": "hls_getTransactionCount", "params": [string, string]}

**Response:**

The hex encoded number of transactions.

**Example:**

::

    <<
    {"method": "hls_getTransactionCount", "params": ['0x9c8b20E830c0Db83862892Fc141808eA6a51FEa2', '0x1']}
    >>
    0x1


hls_protocolVersion
~~~~~~~~~~~~~~~~~~~

Returns the current Helios protocol version.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_protocolVersion", "params": []}

**Response:**

The hex encoded number of transactions.

**Example:**

::

    <<
    {"method": "hls_protocolVersion", "params": []}
    >>
    0x3f


hls_syncing
~~~~~~~~~~~

Tells you whether the node is syncing or not.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_syncing", "params": []}

**Response:**

Will return True if the node is syncing, or False if it is not syncing.

**Example:**

::

    <<
    {"method": "hls_syncing", "params": []}
    >>
    False




hls_getHistoricalGasPrice
~~~~~~~~~~~~~~~~~~~~~~~~~

Gets the historical minimum gas price for each 100 seconds going back about 10,000 seconds.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_getHistoricalGasPrice", "params": []}

**Response:**

Returns a list of [hex encoded timestamp, hex encoded minimum gas price] lists.

**Example:**

::

    <<
    {"method": "hls_getHistoricalGasPrice", "params": []}
    >>
    [['0x5d38c4dc', '0x2'],
     ['0x5d38c540', '0x2'],
     ['0x5d38c5a4', '0x2'],
     ['0x5d38c608', '0x3'],
     ['0x5d38c66c', '0x3'],
     ['0x5d38c6d0', '0x3'],
     ['0x5d38c734', '0x3'],
     ['0x5d38c798', '0x3'],
     ['0x5d38c7fc', '0x3'],
     ['0x5d38c860', '0x3']]...


hls_getApproximateHistoricalNetworkTPCCapability
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gets the approximate transactions per 100 seconds that the network will begin to throttle transactions by increasing the minimum gas price.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_getApproximateHistoricalNetworkTPCCapability", "params": []}

**Response:**

Returns a list of [hex encoded timestamp, hex encoded transactions per 100 seconds] lists.

**Example:**

::

    <<
    {"method": "hls_getApproximateHistoricalNetworkTPCCapability", "params": []}
    >>
    [['0x5d38c798', '0x161f'],
     ['0x5d38c7fc', '0x23ed'],
     ['0x5d38c860', '0x192c'],
     ['0x5d38c8c4', '0x2291'],
     ['0x5d38c928', '0x21a0'],
     ['0x5d38c98c', '0x1c0e'],
     ['0x5d38c9f0', '0x141c'],
     ['0x5d38ca54', '0x22b1'],
     ['0x5d38cab8', '0x2224'],
     ['0x5d38cb1c', '0x1978']]...


hls_getApproximateHistoricalTPC
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gets the approximate historical transactions per 100 seconds. This may not reflect the actual transaction volume, but it is used for the throttling system.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_getApproximateHistoricalTPC", "params": []}

**Response:**

Returns a list of [hex encoded timestamp, hex encoded transactions per 100 seconds] lists.

**Example:**

::

    <<
    {"method": "hls_getApproximateHistoricalTPC", "params": []}
    >>
    [['0x5d38c158', '0x0'],
     ['0x5d38c1bc', '0x2'],
     ['0x5d38c220', '0x0'],
     ['0x5d38c284', '0x0'],
     ['0x5d38c2e8', '0x1'],
     ['0x5d38c34c', '0x0'],
     ['0x5d38c3b0', '0x4'],
     ['0x5d38c414', '0x0']]...



hls_getApproximateHistoricalTPC
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gets the approximate historical transactions per 100 seconds. This may not reflect the actual transaction volume, but it is used for the throttling system.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_getApproximateHistoricalTPC", "params": []}

**Response:**

Returns a list of [hex encoded timestamp, hex encoded transactions per 100 seconds] lists.

**Example:**

::

    <<
    {"method": "hls_getApproximateHistoricalTPC", "params": []}
    >>
    [['0x5d38c158', '0x0'],
     ['0x5d38c1bc', '0x2'],
     ['0x5d38c220', '0x0'],
     ['0x5d38c284', '0x0'],
     ['0x5d38c2e8', '0x1'],
     ['0x5d38c34c', '0x0'],
     ['0x5d38c3b0', '0x4'],
     ['0x5d38c414', '0x0']]...



hls_getBlockNumber
~~~~~~~~~~~~~~~~~~

Returns the block number of the newest block, or the newest block before the specified timestamp.

**Parameters:**

1. The hex encoded chain address.
2. A hex encoded timestamp. This defaults to 'latest' to return the block number of the current head.

**RPC Call:**

::

    {"method": "hls_getBlockNumber", "params": [string, string]}

**Response:**

Returns a hex encoded block number.

**Example:**

::

    <<
    {"method": "hls_getBlockNumber", "params": ['0x7cB6Ff697d0f7aC22A3CB8056314F5F1a72CC15e', 'latest']}
    >>
    0x1


hls_getBlockCreationParams
~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns a dictionary containing all the required information to create and sign a block.

**Parameters:**

1. The hex encoded chain address.

**RPC Call:**

::

    {"method": "hls_getBlockCreationParams", "params": [string]}

**Response:**

Returns a dictionary containing all the required information to create and sign a block. Includes the next block number, it's parent hash, the next transaction nonce, any recievable transactions, the hex encoded reward bundle.

**Example:**

::

    <<
    {"method": "hls_getBlockCreationParams", "params": ['0x7cB6Ff697d0f7aC22A3CB8056314F5F1a72CC15e']}
    >>
    {'block_number': '0x2',
     'parent_hash': '0xf58bf29eae9e1303f6d34a5faeb5961de141294a3ff2370e6dd9a431ad3cc19e',
     'nonce': '0x1',
     'receive_transactions': [],
     'reward_bundle': '0xc5c180c280c0'}


hls_getBlockByHash
~~~~~~~~~~~~~~~~~~

Returns information about a block by hash.

**Parameters:**

1. The hex encoded block hash.
2. Boolean - If true it returns the full transaction objects, if false only the hashes of the transactions.

**RPC Call:**

::

    {"method": "hls_getBlockByHash", "params": [string, boolean]}

**Response:**

Returns a dictionary containing all of the block information.

**Example with receive transactions:**

::

    <<
    {"method": "hls_getBlockByHash", "params": ['0xf58bf29eae9e1303f6d34a5faeb5961de141294a3ff2370e6dd9a431ad3cc19e', true]}
    >>
    {'chainAddress': '0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e',
     'sender': '0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e',
     'extraData': '0x',
     'gasLimit': '0x1df5e76',
     'gasUsed': '0x0',
     'hash': '0x1d26b77e59380fe2be3c79b012f6f6e676d3def5af4b1519dd2e50ce11734d6f',
     'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
     'number': '0x0',
     'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
     'rewardHash': '0xb4f5375844e96b776d7a947561a4f9d045f5e80d06921d96e463cce078a246cc',
     'accountHash': '0xf5304272e41c2301efb2804cb2ebbb27cfe160db13bc9da3e3567584bb48787c',
     'receiptsRoot': '0xb64408da6b8fe39ab764af88ece1e8cca1c35fd988db57806e99138c629365a0',
     'timestamp': '0x5d38c3cc',
     'accountBalance': '0xde0b6b3a7640000',
     'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
     'receiveTransactionsRoot': '0xf58d7f99c900867fd86fe434b056a72a4c870a885b857edf31d3c23a5e1d0853',
     'size': '0x28c',
     'transactions': [],
     'receiveTransactions': [{'senderBlockHash': '0x0506ebe2b69cd5619f926a8f1590347f3f78d04007ef6b477b954d53c9061995',
       'sendTransactionHash': '0xcea1c36aaaa13906e22d0d2b24c56718d6de6f4ea42e726ea465875ecb04f66c',
       'isRefund': '0x0',
       'remainingRefund': '0x0',
       'isReceive': '0x1',
       'hash': '0xc1d3a88f66469541048df37542f9942d711ba5c05434da474cf77bb9e42b81e0',
       'from': '0x0d1630cb77c00d95f7fa32bccfe80043639681be',
       'value': '0xde0b6b3a7640000',
       'gasPrice': '0xb2d05e00',
       'to': '0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e',
       'gasUsed': '0x0',
       'transactionIndex': '0x0',
       'blockHash': '0x1d26b77e59380fe2be3c79b012f6f6e676d3def5af4b1519dd2e50ce11734d6f'}],
     'rewardBundle': {'rewardType1': {'amount': '0x0'},
      'rewardType2': {'amount': '0x0', 'proof': []},
      'hash': '0xb4f5375844e96b776d7a947561a4f9d045f5e80d06921d96e463cce078a246cc',
      'isReward': '0x1'}}


**Example with send transactions:**

::

    <<
    {"method": "hls_getBlockByHash", "params": ['0xf58bf29eae9e1303f6d34a5faeb5961de141294a3ff2370e6dd9a431ad3cc19e', true]}
    >>
    {'chainAddress': '0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e',
     'sender': '0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e',
     'extraData': '0x',
     'gasLimit': '0x1df5e76',
     'gasUsed': '0x5208',
     'hash': '0xf58bf29eae9e1303f6d34a5faeb5961de141294a3ff2370e6dd9a431ad3cc19e',
     'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
     'number': '0x1',
     'parentHash': '0x1d26b77e59380fe2be3c79b012f6f6e676d3def5af4b1519dd2e50ce11734d6f',
     'rewardHash': '0xb4f5375844e96b776d7a947561a4f9d045f5e80d06921d96e463cce078a246cc',
     'accountHash': '0x7984542686dbb4bdac445cf08988841d9ac0b6e31e6449feae8c08849ddf2597',
     'receiptsRoot': '0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2',
     'timestamp': '0x5d38c401',
     'accountBalance': '0x6f0220d7f131000',
     'transactionsRoot': '0x54566cf1f00d94682f58c31b8aafec2c86c274b62439e9ca2d37c6f8da405f6b',
     'receiveTransactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
     'size': '0x2b6',
     'transactions': [{'nonce': '0x0',
       'gasPrice': '0xb2d05e00',
       'gas': '0xc3500',
       'to': '0x0d1630cb77c00d95f7fa32bccfe80043639681be',
       'value': '0x6f05b59d3b20000',
       'data': '0x',
       'v': '0x26',
       'r': '0x533d1edbb0307b1ac7298289a7e93f6811c6c4b6ff41139fd587f591f564fad9',
       's': '0x790283718e571ecc52e0a3f06a238a46830f4256ea74b0c21cd62630867c3e12',
       'from': '0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e',
       'hash': '0xae80fe044de77de5fdcf8f96bc800eb380e176b23d216d8f03da571217ede266',
       'gasUsed': '0x5208',
       'blockHash': '0xf58bf29eae9e1303f6d34a5faeb5961de141294a3ff2370e6dd9a431ad3cc19e',
       'blockNumber': '0x1',
       'transactionIndex': '0x0',
       'input': '0x',
       'isReceive': '0x0'}],
     'receiveTransactions': [],
     'rewardBundle': {'rewardType1': {'amount': '0x0'},
      'rewardType2': {'amount': '0x0', 'proof': []},
      'hash': '0xb4f5375844e96b776d7a947561a4f9d045f5e80d06921d96e463cce078a246cc',
      'isReward': '0x1'}}



hls_getBlockByNumber
~~~~~~~~~~~~~~~~~~~~

Returns information about a block by number and chain address.

**Parameters:**

1. The hex encoded block number.
2. The hex encoded chain address.
3. Boolean - If true it returns the full transaction objects, if false only the hashes of the transactions.

**RPC Call:**

::

    {"method": "hls_getBlockByNumber", "params": [string, string, boolean]}

**Response:**

Returns the same as getBlockByHash


hls_sendRawBlock
~~~~~~~~~~~~~~~~

Sends a completed signed block to the network.

**Parameters:**

1. The hex encoded, RLP encoded raw block.

**RPC Call:**

::

    {"method": "hls_sendRawBlock", "params": [string]}

**Response:**

Returns True if the block passed the preliminary validation. The block is then sent to another process to import the block and perform full validation. It may pass preliminary validation but fail the final validation and not be imported.

**Example:**

::

    <<
    {"method": "hls_sendRawBlock", "params": ['0xf9015cf8e3949c8b20e830c0db83862892fc141808ea6a51fea2a01c60210ac93060c2ea586186002d7690a05e49d43b30906818ac670c40bfd72ea0de5b3125fb42edc3887bc10790e4d015e82a4665be5af57948c7017518bcca6fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42104845d38e46380a0b4f5375844e96b776d7a947561a4f9d045f5e80d06921d96e463cce078a246cc25a0e952aa6e5cf510ff52b4997050120246aa059eb2f3425f647f68f1bcc9f17ef6a01a9b9790f00fa16a6208bebd4ff76750af3d2afc188f96ef1ee9a317a890b9f5f86ef86c0384b2d05e00830c3500940d1630cb77c00d95f7fa32bccfe80043639681be880de0b6b3a76400008026a09e5fe33a2251cad834fe0a2a8be052cee2213028ce37197cc4b4e7ca79927f76a00d7c0e8645af233d17de67d50203a770a354d69fc567e5d931ef129ac26916d8c0c5c180c280c0']}
    >>
    true


hls_sendRawBlock
~~~~~~~~~~~~~~~~

Sends a completed signed block to the network.

**Parameters:**

1. The hex encoded, RLP encoded raw block.

**RPC Call:**

::

    {"method": "hls_sendRawBlock", "params": [string]}

**Response:**

Returns True if the block passed the preliminary validation. The block is then sent to another process to import the block and perform full validation. It may pass preliminary validation but fail the final validation and not be imported.

**Example:**

::

    <<
    {"method": "hls_sendRawBlock", "params": ['0xf9015cf8e3949c8b20e830c0db83862892fc141808ea6a51fea2a01c60210ac93060c2ea586186002d7690a05e49d43b30906818ac670c40bfd72ea0de5b3125fb42edc3887bc10790e4d015e82a4665be5af57948c7017518bcca6fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42104845d38e46380a0b4f5375844e96b776d7a947561a4f9d045f5e80d06921d96e463cce078a246cc25a0e952aa6e5cf510ff52b4997050120246aa059eb2f3425f647f68f1bcc9f17ef6a01a9b9790f00fa16a6208bebd4ff76750af3d2afc188f96ef1ee9a317a890b9f5f86ef86c0384b2d05e00830c3500940d1630cb77c00d95f7fa32bccfe80043639681be880de0b6b3a76400008026a09e5fe33a2251cad834fe0a2a8be052cee2213028ce37197cc4b4e7ca79927f76a00d7c0e8645af233d17de67d50203a770a354d69fc567e5d931ef129ac26916d8c0c5c180c280c0']}
    >>
    true


hls_getNewestBlocks
~~~~~~~~~~~~~~~~~~~

Gets the newest blocks across all of the blockchains in the DAG, or if chain address is specified, it will get the newest blocks on a given chain.

**Parameters:**

1. The hex encoded number of blocks to return. Max of 10.
2. The hex encoded index to start at, counting backwards from the chain head, with the chain head at index 0. For example, 0 is the newest block, 3 is the 3rd newest block, 10 is the 10th newest block etc...
3. A block hash. Only return blocks newer than this block hash. So if there are only x blocks newer than the this parameter, then it will only return x blocks.
4. Chain address.
5. Boolean - whether or not to include transactions.

**RPC Call:**

::

    {"method": "hls_getNewestBlocks", "params": [string, string, string, string, boolean]}

**Response:**

Returns a list of blocks.

**Example:**

::

    <<
    {"method": "hls_getNewestBlocks", "params": ['0xA', '0x0', '0x', '0x', false]}
    >>
    [a list of blocks]


hls_getConnectedNodes
~~~~~~~~~~~~~~~~~~~~~

Gets a list fo dictionaries containing information about the nodes currently connected to this one.

**Parameters:**

None

**RPC Call:**

::

    {"method": "hls_getConnectedNodes", "params": []}

**Response:**

Returns a list of connected nodes. url, and ipAddress are utf-8 hex encoded text strings. stake is the hex encoded stake in Wei. requestsSent, udpPort, and tcpPort are hex encoded integers. failedRequests is a hex encoded integer. averageResponseTime is a hex encoded integer, which is in microseconds.

**Example:**

::

    <<
    {"method": "hls_getConnectedNodes", "params": []}
    >>
    [{'url': '0x3c4e6f64652830786138646337643131383031666365623630313864663337376263333762616435643466353830643163333663353762313035353539356461616564353466376563313562613163323437623331376462316235643337653433396465303765343264626335616530333764643930663665373765346336393435336335663064403134322e35382e3132322e3230393a3330333033293e',
      'ipAddress': '0x3134322e35382e3132322e323039',
      'udpPort': '0x765f',
      'tcpPort': '0x765f',
      'stake': '0x0',
      'requestsSent': '0x0',
      'failedRequests': '0x0',
      'averageResponseTime': '0x0'},
     {'url': '0x3c4e6f646528307837333163323361366536386633616562613731303361353635633963666630326161316237343565353536643935636361616338643234326633653537653861653164666264396539366339653237316263626537663636336439646665323735346239303431653364623936333364633231373632323964646236326337624036362e34322e38322e3234363a3330333033293e',
      'ipAddress': '0x36362e34322e38322e323436',
      'udpPort': '0x765f',
      'tcpPort': '0x765f',
      'stake': '0x0',
      'requestsSent': '0x0',
      'failedRequests': '0x0',
      'averageResponseTime': '0x0'},
     {'url': '0x3c4e6f64652830783136613564333037623031353264336533653439653862316632663038633430336137623862326632373636376165306566313034383630313933323662373163353066616337623263666336633237386361366162633534626638653831653337366136613832393936666661656135393961656138356336663566383331403134322e35382e34392e32353a3330333033293e',
      'ipAddress': '0x3134322e35382e34392e3235',
      'udpPort': '0x765f',
      'tcpPort': '0x765f',
      'stake': '0x0',
      'requestsSent': '0x0',
      'failedRequests': '0x0',
      'averageResponseTime': '0x0'}]




