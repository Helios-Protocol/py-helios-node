import pytest

from eth_utils import (
    to_canonical_address,
)
from helios.dev_tools import create_dev_test_random_blockchain_database, create_predefined_blockchain_database
from hvm import TestnetChain
from hvm.chains.testnet import TestnetTesterChain, TESTNET_GENESIS_PRIVATE_KEY, TESTNET_GENESIS_PARAMS, \
    TESTNET_GENESIS_STATE

from hvm.vm.message import (
    Message,
)
from hvm.vm.forks.frontier.computation import (
    FrontierComputation,
)
from hvm.vm.transaction_context import (
    BaseTransactionContext,
)


NORMALIZED_ADDRESS_A = "0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
NORMALIZED_ADDRESS_B = "0xcd1722f3947def4cf144679da39c4c32bdc35681"
CANONICAL_ADDRESS_A = to_canonical_address("0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6")
CANONICAL_ADDRESS_B = to_canonical_address("0xcd1722f3947def4cf144679da39c4c32bdc35681")

from hvm.db.backends.memory import MemoryDB
from hvm.constants import random_private_keys

from eth_keys import keys
def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)
RECEIVER5 = get_primary_node_private_helios_key(5)

@pytest.fixture
def state():
    testdb1 = MemoryDB()
    create_predefined_blockchain_database(testdb1)
    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    state = chain.get_vm().state
    return state

from hvm.constants import ZERO_ADDRESS, ZERO_HASH32

@pytest.fixture
def transaction_context():
    tx_context = BaseTransactionContext(
        send_tx_hash=ZERO_HASH32,
        caller_chain_address=SENDER.public_key.to_canonical_address(),
        gas_price=1,
        origin=SENDER.public_key.to_canonical_address(),
    )
    return tx_context


@pytest.fixture
def message():
    message = Message(
        to=RECEIVER.public_key.to_canonical_address(),
        sender=SENDER.public_key.to_canonical_address(),
        value=100,
        data=b'',
        code=b'',
        gas=100,
    )
    return message


@pytest.fixture
def computation(message, transaction_context, state):
    computation = FrontierComputation(
        state=state,
        message=message,
        transaction_context=transaction_context,
    )
    return computation


@pytest.fixture
def child_message(computation):
    child_message = computation.prepare_child_message(
        gas=100,
        to=RECEIVER.public_key.to_canonical_address(),
        value=200,
        data=b'',
        code=b''
    )
    return child_message


@pytest.fixture
def child_computation(computation, child_message):
    child_computation = computation.generate_child_computation(child_message)
    return child_computation


def test_generate_child_computation(computation, child_computation):
    assert computation.transaction_context.gas_price == child_computation.transaction_context.gas_price  # noqa: E501
    assert computation.transaction_context.origin == child_computation.transaction_context.origin  # noqa: E501
