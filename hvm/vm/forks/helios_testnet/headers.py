from hvm.constants import (
    GENESIS_GAS_LIMIT
)
from hvm.validation import (
    validate_header_params_for_configuration,
)
from hvm.utils.headers import (
    compute_gas_limit,
)

from hvm.rlp.headers import BlockHeader


def create_helios_testnet_header_from_parent(parent_header, **header_params):
    if 'gas_limit' not in header_params:
#        header_params['gas_limit'] = compute_gas_limit(
#            parent_header,
#            gas_limit_floor=GENESIS_GAS_LIMIT,
#        )
        header_params['gas_limit'] = compute_gas_limit()

    header = BlockHeader.from_parent(parent=parent_header, **header_params)

    return header


def configure_helios_testnet_header(vm, **header_params):
    validate_header_params_for_configuration(header_params)
    
    with vm.block.header.build_changeset(**header_params) as changeset:
        header = changeset.commit()
        
    return header
