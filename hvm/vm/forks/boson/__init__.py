from hvm.vm.forks.boson.consensus import BosonConsensusDB
from .constants import (
    EIP658_TRANSACTION_STATUS_CODE_FAILURE,
    EIP658_TRANSACTION_STATUS_CODE_SUCCESS,
)

from .validation import validate_boson_transaction_against_header

from .blocks import (
    BosonBlock, BosonQueueBlock, BosonMicroBlock)

from .headers import (
    create_boson_header_from_parent, configure_boson_header)
from .state import BosonState
from hvm.vm.base import VM

from hvm.rlp.receipts import (
    Receipt,
)

from .transactions import (
    HeliosTestnetTransaction,
    HeliosTestnetReceiveTransaction,
)

from .computation import HeliosTestnetComputation

from hvm.rlp.headers import BaseBlockHeader

from hvm.vm.forks.helios_testnet import make_helios_testnet_receipt



def make_boson_receipt(base_header: BaseBlockHeader,
                                computation: HeliosTestnetComputation,
                                send_transaction: HeliosTestnetTransaction,
                                receive_transaction: HeliosTestnetReceiveTransaction = None,
                                refund_transaction: HeliosTestnetReceiveTransaction = None,
                                ) -> Receipt:

    return make_helios_testnet_receipt(base_header,
                                       computation,
                                       send_transaction,
                                       receive_transaction,
                                       refund_transaction)


class BosonVM(VM):
    # fork name
    fork = 'boson'

    # classes
    micro_block_class = BosonMicroBlock
    block_class = BosonBlock
    queue_block_class = BosonQueueBlock
    _state_class = BosonState

    # Methods
    create_header_from_parent = staticmethod(create_boson_header_from_parent)
    configure_header = configure_boson_header
    make_receipt = staticmethod(make_boson_receipt)
    validate_transaction_against_header = validate_boson_transaction_against_header
    consensus_db_class = BosonConsensusDB