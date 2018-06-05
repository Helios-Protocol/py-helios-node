from evm.constants import (
    GENESIS_GAS_LIMIT
)
from evm.validation import (
    validate_header_params_for_configuration,
)
from evm.utils.headers import (
    compute_gas_limit,
)

from evm.rlp.headers import BlockHeader


def create_helios_testnet_header_from_parent(parent_header, **header_params):
    if 'gas_limit' not in header_params:
        header_params['gas_limit'] = compute_gas_limit(
            parent_header,
            gas_limit_floor=GENESIS_GAS_LIMIT,
        )

    header = BlockHeader.from_parent(parent=parent_header, **header_params)

    return header


def configure_helios_testnet_header(vm, **header_params):
    validate_header_params_for_configuration(header_params)

    return vm.block.header
