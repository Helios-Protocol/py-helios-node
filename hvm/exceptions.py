class PyEVMError(Exception):
    """
    Base class for all py-hvm errors.
    """
    pass


class VMNotFound(PyEVMError):
    """
    Raised when no VM is available for the provided block number.
    """
    pass

class NoGenesisBlockPresent(PyEVMError):
    """
    Raised when a block is imported but there is no genesis block.
    """
    pass


class StateRootNotFound(PyEVMError):
    """
    Raised when the requested state root is not present in our DB.
    """
    pass


class HeaderNotFound(PyEVMError):
    """
    Raised when a header with the given number/hash does not exist.
    """
    

class BlockNotFound(PyEVMError):
    """
    Raised when the block with the given number/hash does not exist.
    """
    pass

class BlockOnWrongChain(PyEVMError):
    """
    Raised when a block interacts with a chain it doesnt belong to
    """
    pass


class RewardProofSenderBlockMissing(PyEVMError):
    """
    Raised when a reward block is imported with provided proof from peers, but we don't have an up to date peer chain yet
    so we cannot verify the proof. Need to safe the block as unprocessed until we download the peer chain.
    """
    pass

class NoLocalRootHashTimestamps(PyEVMError):
    """
    Raised when there are no local root hash timestamps
    """
    pass

class LocalRootHashNotInConsensus(PyEVMError):
    """
    Raised when there are no local root hash timestamps
    """
    pass

class LocalRootHashNotAsExpected(PyEVMError):
    """
    Raised after importing blocks and our root hash doesnt match what it should be
    """
    pass


class IncorrectBlockType(PyEVMError):
    """
    Raised when the block is queueblock when it should be block or vice-versa
    """
    pass

class IncorrectBlockHeaderType(PyEVMError):
    """
    Raised when the block is queueblock when it should be block or vice-versa
    """
    pass

class NotEnoughTimeBetweenBlocks(PyEVMError):
    """
    Raised when there is not enough time between blocks. WHO WOULD HAVE GUESSED?
    """
    pass

class CannotCalculateStake(PyEVMError):
    """
    Raised when a function tries to calculate the stake for an address where we are missing information. for example, if we dont have their chain.
    """
    pass

class ReceivableTransactionNotFound(PyEVMError):
    """
    Raised when a A receive transaction tries to receive a transaction that wasnt sent
    """
    pass

class HistoricalNetworkTPCMissing(PyEVMError):
    """
    Raised when a historical network tpc is missing for a certain timestamp
    """
    pass

class NotEnoughProofsOrStakeForRewardType2Proof(PyEVMError):
    """
    Raised when all of the proof we have for a reward type 2 does not meet the minimum requirement
    """
    pass

class RewardAmountRoundsToZero(PyEVMError):
    """
    Raised when a node attempts to create a reward block that has amount = 0 for all kinds of rewards. This will occur if not enough time has passed since the last reward.
    """
    pass

class NotEnoughDataForHistoricalMinGasPriceCalculation(PyEVMError):
    """
    Raised when there is not enough historical TPC to perform a calculation. Can occur when the genesis node just starts
    """
    pass

class HistoricalMinGasPriceError(PyEVMError):
    """
    Raised when a historical network tpc is missing for a certain timestamp
    """
    pass


class TransactionNotFound(PyEVMError):
    """
    Raised when the transaction with the given hash or block index does not exist.
    """
    pass

class InvalidHeadRootTimestamp(PyEVMError):
    """
    Raised when a timestamp based head hash is loaded or saved with invalid timestamp
    """
    pass

class NoChronologicalBlocks(PyEVMError):
    """
    Raised When there are no new blocks within the chronological block windows
    """
    pass

class ParentNotFound(HeaderNotFound):
    """
    Raised when the parent of a given block does not exist.
    """
    pass

class UnprocessedBlockNotAllowed(PyEVMError):
    """
    Raised when an unprocessed block is imported when it is not allowed
    """
    pass

class UnprocessedBlockChildIsProcessed(PyEVMError):
    """
    Raised when a child of an unprocessed block has been processed for some reason
    """
    pass

class ReplacingBlocksNotAllowed(PyEVMError):
    """
    Raised when a block tries to replace another block when it is not allowed
    """
    pass

class CanonicalHeadNotFound(PyEVMError):
    """
    Raised when the chain has no canonical head.
    """
    pass

class TriedImportingGenesisBlock(PyEVMError):
    """
    Raised when the genesis block on the genesis chain is attempted to be overwritten
    """
    pass

class TriedDeletingGenesisBlock(PyEVMError):
    """
    Raised when the genesis block on the genesis chain is attempted to be deleted
    """
    pass


class CollationHeaderNotFound(PyEVMError):
    """
    Raised when the collation header for the given shard and period does not exist in the database.
    """
    pass


class SyncerOutOfOrder(PyEVMError):
    """
    Syncer process has hit a snag and is out of order. For example, regular chain syncer went before it should.
    """
    pass


class CollationBodyNotFound(PyEVMError):
    """
    Raised when the collation body for the given shard and period does not exist in the database.
    """
    pass


class CanonicalCollationNotFound(PyEVMError):
    """
    Raised when no collation for the given shard and period has been marked as canonical.
    """
    pass

class AppendHistoricalRootHashTooOld(PyEVMError):
    """
    Raised when you try to append a historical root hash that is older than the oldest one in our database. can only append newer historical root hashes
    """
    pass


class ValidationError(PyEVMError):
    """
    Raised when something does not pass a validation check.
    """
    pass

class JournalDbNotActivated(PyEVMError):
    """
    Raised when someone tries to discard, save, persist a db, when it is not actually a journaldb
    """
    pass


class Halt(PyEVMError):
    """
    Raised when an opcode function halts vm execution.
    """
    pass


class VMError(PyEVMError):
    """
    Base class for errors raised during VM execution.
    """
    burns_gas = True
    erases_return_data = True


class OutOfGas(VMError):
    """
    Raised when a VM execution has run out of gas.
    """
    pass


class InsufficientStack(VMError):
    """
    Raised when the stack is empty.
    """
    pass


class FullStack(VMError):
    """
    Raised when the stack is full.
    """
    pass


class InvalidJumpDestination(VMError):
    """
    Raised when the jump destination for a JUMPDEST operation is invalid.
    """
    pass


class InvalidInstruction(VMError):
    """
    Raised when an opcode is invalid.
    """
    pass


class InsufficientFunds(VMError):
    """
    Raised when an account has insufficient funds to transfer the
    requested value.
    """
    pass

class ReceiveTransactionIncorrectSenderBlockHash(VMError):
    """
    Raised when a receive transaction is found that has a sender block hash
    that doesnt match the one in our database.
    """
    pass


class ReceivingTransactionForWrongWallet(VMError):
    """
    Raised when a someone tries to receive a transaction sent to someone else.
    """
    pass




class StackDepthLimit(VMError):
    """
    Raised when the call stack has exceeded it's maximum allowed depth.
    """
    pass


class ContractCreationCollision(VMError):
    """
    Raised when there was an address collision during contract creation.
    """
    pass


class IncorrectContractCreationAddress(VMError):
    """
    Raised when the address provided by transaction does not
    match the calculated contract creation address.
    """
    pass


class Revert(VMError):
    """
    Raised when the REVERT opcode occured
    """
    burns_gas = False
    erases_return_data = False


class WriteProtection(VMError):
    """
    Raised when an attempt to modify the state database is made while
    operating inside of a STATICCALL context.
    """
    pass


class OutOfBoundsRead(VMError):
    """
    Raised when an attempt was made to read data beyond the
    boundaries of the buffer (such as with RETURNDATACOPY)
    """
    pass

class AttemptedToAccessExternalStorage(VMError):
    """
    Raised when a contract calls another contract and attempts
    to use the storage in the other contract. This is not allowed
    on Helios. Use DelegateCall instead of Call.
    """
    pass
