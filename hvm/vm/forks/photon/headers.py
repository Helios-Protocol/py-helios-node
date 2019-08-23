from hvm.vm.forks.boson import create_boson_header_from_parent, configure_boson_header


def create_photon_header_from_parent(parent_header, **header_params):
    return create_boson_header_from_parent(parent_header, **header_params)


def configure_photon_header(vm, **header_params):
    return configure_boson_header(vm, **header_params)
