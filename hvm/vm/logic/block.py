from hvm import constants
from hvm.exceptions import DepreciatedVMFunctionality


def blockhash(computation):
    raise DepreciatedVMFunctionality("blockhash has been removed.")


def timestamp(computation):
    computation.stack_push_int(computation.state.timestamp)


def number(computation):
    computation.stack_push_int(computation.state.block_number)


def difficulty(computation):
    raise DepreciatedVMFunctionality("difficulty has been removed.")


def gaslimit(computation):
    computation.stack_push_int(computation.state.gas_limit)
