from hvm.vm.forks.helios_testnet import create_helios_testnet_header_from_parent, configure_helios_testnet_header


def create_boson_header_from_parent(parent_header, **header_params):
    return create_helios_testnet_header_from_parent(parent_header, **header_params)


def configure_boson_header(vm, **header_params):
    return configure_helios_testnet_header(vm, **header_params)
