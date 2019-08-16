# Allow blocks importing from rpc that are at most this number of seconds old.
MAX_ALLOWED_AGE_OF_NEW_RPC_BLOCK = 60
# Once the import queue reaches this length, the node will reject rpc blocks and transactions and respond by saying
# that we are still syncing
MAX_ALLOWED_LENGTH_BLOCK_IMPORT_QUEUE = 3