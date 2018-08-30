#from cytoolz import (
#    merge,
#)
#
#from hvm import precompiles
#from hvm.utils.address import (
#    force_bytes_to_address,
#)


from cytoolz import (
    merge,
)

from hvm import precompiles
from hvm.utils.address import (
    force_bytes_to_address,
)

from eth_hash.auto import keccak

from hvm import constants

from hvm.utils.hexadecimal import (
    encode_hex,
)

from hvm.vm.computation import (
    BaseComputation
)

from hvm.exceptions import (
    OutOfGas,
    InsufficientFunds,
    StackDepthLimit,
    ReceivableTransactionNotFound,
)


from .constants import EIP170_CODE_SIZE_LIMIT



from .opcodes import HELIOS_TESTNET_OPCODES


FRONTIER_PRECOMPILES = {
    force_bytes_to_address(b'\x01'): precompiles.ecrecover,
    force_bytes_to_address(b'\x02'): precompiles.sha256,
    force_bytes_to_address(b'\x03'): precompiles.ripemd160,
    force_bytes_to_address(b'\x04'): precompiles.identity,
}
    
BYZANTIUM_PRECOMPILES = merge(
    FRONTIER_PRECOMPILES,
    {
        force_bytes_to_address(b'\x05'): precompiles.modexp,
        force_bytes_to_address(b'\x06'): precompiles.ecadd,
        force_bytes_to_address(b'\x07'): precompiles.ecmul,
        force_bytes_to_address(b'\x08'): precompiles.ecpairing,
    },
)    
HELIOS_TESTNET_PRECOMPILES = BYZANTIUM_PRECOMPILES   


class HeliosTestnetComputation(BaseComputation):
    """
    A class for all execution computations in the ``Byzantium`` fork.
    Inherits from :class:`~hvm.vm.forks.spurious_dragon.computation.SpuriousDragonComputation`
    """
    # Override
    opcodes = HELIOS_TESTNET_OPCODES
    _precompiles = HELIOS_TESTNET_PRECOMPILES
    
    def apply_message(self, validate = True):
        snapshot = self.state.snapshot()

        if self.msg.depth > constants.STACK_DEPTH_LIMIT:
            raise StackDepthLimit("Stack depth limit reached")

        if self.msg.should_transfer_value and self.msg.value:
            if self.transaction_context.is_receive:
                #this is a receive transaction
                try:
                    self.state.account_db.delete_receivable_transaction(self.msg.storage_address, self.transaction_context.send_tx_hash)
                except ReceivableTransactionNotFound as e:
                    if validate:
                        raise e
                        
                self.state.account_db.delta_balance(self.msg.storage_address, self.msg.value)
                self.logger.debug(
                    "TRANSFERRED: %s into %s",
                    self.msg.value,
                    encode_hex(self.msg.storage_address),
                )
            else:
                if validate:
                    #this is a send transaction
                    sender_balance = self.state.account_db.get_balance(self.msg.sender)
        
                    if sender_balance < self.msg.value:
                        raise InsufficientFunds(
                            "Insufficient funds: {0} < {1}".format(sender_balance, self.msg.value)
                        )
    
                self.state.account_db.delta_balance(self.msg.sender, -1 * self.msg.value)
                
                self.logger.debug(
                    "TRANSFERRED: %s from %s to pending transactions",
                    self.msg.value,
                    encode_hex(self.msg.sender),
                )

        self.state.account_db.touch_account(self.msg.storage_address)

        computation = self.apply_computation(
            self.state,
            self.msg,
            self.transaction_context,
        )

        if computation.is_error:
            self.state.revert(snapshot)
        else:
            self.state.commit(snapshot)

        return computation
    
    
    def apply_create_message(self):
        snapshot = self.state.snapshot()

        # EIP161 nonce incrementation
        self.state.account_db.increment_nonce(self.msg.storage_address)

        computation = self.apply_message()

        if computation.is_error:
            self.state.revert(snapshot)
            return computation
        else:
            contract_code = computation.output

            if contract_code and len(contract_code) >= EIP170_CODE_SIZE_LIMIT:
                computation._error = OutOfGas(
                    "Contract code size exceeds EIP170 limit of {0}.  Got code of "
                    "size: {1}".format(
                        EIP170_CODE_SIZE_LIMIT,
                        len(contract_code),
                    )
                )
                self.state.revert(snapshot)
            elif contract_code:
                contract_code_gas_cost = len(contract_code) * constants.GAS_CODEDEPOSIT
                try:
                    computation.consume_gas(
                        contract_code_gas_cost,
                        reason="Write contract code for CREATE",
                    )
                except OutOfGas as err:
                    # Different from Frontier: reverts state on gas failure while
                    # writing contract code.
                    computation._error = err
                    self.state.revert(snapshot)
                else:
                    if self.logger:
                        self.logger.debug(
                            "SETTING CODE: %s -> length: %s | hash: %s",
                            encode_hex(self.msg.storage_address),
                            len(contract_code),
                            encode_hex(keccak(contract_code))
                        )

                    self.state.account_db.set_code(self.msg.storage_address, contract_code)
                    self.state.commit(snapshot)
            else:
                self.state.commit(snapshot)
            return computation
    
    
    
    
    
