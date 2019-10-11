import pytest

from eth_utils import (
    decode_hex,
    encode_hex,
    hexstr_if_str,
    int_to_big_endian,
    to_bytes,
    to_canonical_address,
)
from hvm import (
    constants
)
from hvm.constants import ZERO_HASH32, ZERO_ADDRESS, BLOCK_GAS_LIMIT, GAS_CALLSTIPEND, CREATE_CONTRACT_ADDRESS
from hvm.utils.address import (
    force_bytes_to_address,
    generate_contract_address, generate_safe_contract_address)
from hvm.db.atomic import (
    AtomicDB
)
from hvm.db.chain import (
    ChainDB
)
from hvm.exceptions import (
    InvalidInstruction,
    VMError,
    ValidationError,
    ForbiddenOperationForSurrogateCall, OutOfGas, ForbiddenOperationForExecutingOnSend)
from hvm.rlp.headers import (
    BlockHeader,
)
from hvm.utils.padding import (
    pad32
)
from hvm.vm import (
    opcode_values
)
from hvm.vm.forks import (
    PhotonVM
)
from hvm.vm.message import (
    Message,
)
from pprint import pprint


NORMALIZED_ADDRESS_A = "0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
NORMALIZED_ADDRESS_B = "0xcd1722f3947def4cf144679da39c4c32bdc35681"
ADDRESS_WITH_CODE = ("0xddd722f3947def4cf144679da39c4c32bdc35681", b'pseudocode')
EMPTY_ADDRESS_IN_STATE = NORMALIZED_ADDRESS_A
ADDRESS_NOT_IN_STATE = NORMALIZED_ADDRESS_B
ADDRESS_WITH_JUST_BALANCE = "0x0000000000000000000000000000000000000001"
CANONICAL_ADDRESS_A = to_canonical_address("0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6")
CANONICAL_ADDRESS_B = to_canonical_address("0xcd1722f3947def4cf144679da39c4c32bdc35681")
CANONICAL_ADDRESS_C = to_canonical_address("0xcd1722f3947def4cf144679da39c4c32bdc35682")
CANONICAL_ADDRESS_D = to_canonical_address("0xcd1722f3947def4cf144679da39c4c32bdc35683")

GENESIS_HEADER = BlockHeader(
    block_number=constants.GENESIS_BLOCK_NUMBER
)


def assemble(*codes):
    return b''.join(
        hexstr_if_str(to_bytes, element)
        for element in codes
    )



def setup_computation(
        vm_class,
        create_address,
        code,
        chain_id=0,
        gas=1000000,
        to=CANONICAL_ADDRESS_A,
        data=b'',
        code_address = None,
        execute_on_send = False,
        is_receive=False,
        is_surrogate=False,
        is_computation_call_origin = False,
        is_create_tx = False):

    message = Message(
        to=to,
        sender=CANONICAL_ADDRESS_B,
        create_address=create_address,
        value=0,
        data=data,
        code=code,
        gas=gas,
        code_address=code_address,
        execute_on_send=execute_on_send
    )

    if is_receive:
        receive_tx_hash = ZERO_HASH32
        this_chain_address = to
    else:
        receive_tx_hash = None
        this_chain_address = CANONICAL_ADDRESS_B

    if is_surrogate:
        tx_code_address = code_address
    else:
        tx_code_address = None

    if is_computation_call_origin:
        tx_origin = CANONICAL_ADDRESS_C
        tx_caller = CANONICAL_ADDRESS_C
    else:
        tx_origin = None
        tx_caller = None

    tx_context = vm_class._state_class.transaction_context_class(
        send_tx_to=to,
        tx_signer=CANONICAL_ADDRESS_B,
        gas_price=1,
        origin=CANONICAL_ADDRESS_B,
        send_tx_hash=ZERO_HASH32,
        this_chain_address=this_chain_address,
        receive_tx_hash=receive_tx_hash,
        tx_execute_on_send=execute_on_send,
        is_receive=is_receive,
        tx_code_address=tx_code_address,
        tx_origin=tx_origin,
        tx_caller=tx_caller
    )


    vm = vm_class(GENESIS_HEADER, ChainDB(AtomicDB()), chain_id)

    computation = vm_class._state_class.computation_class(
        state=vm.state,
        message=message,
        transaction_context=tx_context,
    )
    computation.state.execution_context.computation_call_nonce=0

    return computation


def prepare_general_computation(vm_class, create_address=None, code=b'', chain_id=0, **kwargs):

    computation = setup_computation(vm_class, create_address, code, chain_id, **kwargs)

    computation.state.account_db.touch_account(decode_hex(EMPTY_ADDRESS_IN_STATE))
    computation.state.account_db.set_code(decode_hex(ADDRESS_WITH_CODE[0]), ADDRESS_WITH_CODE[1])

    computation.state.account_db.set_balance(decode_hex(ADDRESS_WITH_JUST_BALANCE), 1)

    return computation


@pytest.mark.parametrize(
    'vm_class, val1, val2, expected',
    (
        (PhotonVM, 2, 4, 6,),
    )
)
def test_add(vm_class, val1, val2, expected):
    computation = prepare_general_computation(vm_class)
    computation.stack_push_int(val1)
    computation.stack_push_int(val2)
    computation.opcodes[opcode_values.ADD](computation)

    result = computation.stack_pop1_int()
    print('result')
    print(result)
    assert result == expected



@pytest.mark.parametrize(
    'vm_class, opcode_value, expected, expect_to_fail',
    (
        (PhotonVM, opcode_values.COINBASE, b'\0' * 20, True),
        # (opcode_values.TIMESTAMP, 1556826898),
        (PhotonVM, opcode_values.NUMBER, 0, False),
        (PhotonVM, opcode_values.DIFFICULTY, 17179869184, True),
        (PhotonVM, opcode_values.GASLIMIT, BLOCK_GAS_LIMIT, False),
    )
)
def test_nullary_opcodes(vm_class, opcode_value, expected, expect_to_fail):
    computation = prepare_general_computation(vm_class)

    if expect_to_fail:
        with pytest.raises(Exception):
            computation.opcodes[opcode_value](computation)
    else:
        computation.opcodes[opcode_value](computation)
        result = computation.stack_pop1_any()
        assert result == expected




@pytest.mark.parametrize(
    'vm_class, val1, val2, expected',
    (
        (PhotonVM, 2, 2, 4,),
    )
)
def test_mul(vm_class, val1, val2, expected):
    computation = prepare_general_computation(vm_class)
    computation.stack_push_int(val1)
    computation.stack_push_int(val2)
    computation.opcodes[opcode_values.MUL](computation)

    result = computation.stack_pop1_int()

    assert result == expected


@pytest.mark.parametrize(
    'vm_class, base, exponent, expected',
    (
        (PhotonVM, 0, 1, 0,),
        (PhotonVM, 0, 0, 1,),
    )
)
def test_exp(vm_class, base, exponent, expected):
    computation = prepare_general_computation(vm_class)
    computation.stack_push_int(exponent)
    computation.stack_push_int(base)
    computation.opcodes[opcode_values.EXP](computation)

    result = computation.stack_pop1_int()

    assert result == expected


@pytest.mark.parametrize(
    # Testcases from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-145.md#shl-shift-left
    'vm_class, val1, val2, expected',
    (
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x00',
            '0x0000000000000000000000000000000000000000000000000000000000000001',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x01',
            '0x0000000000000000000000000000000000000000000000000000000000000002',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0xff',
            '0x8000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x0100',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x0101',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x00',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x01',
            '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0xff',
            '0x8000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x0100',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000000',
            '0x01',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x01',
            '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
        ),
    )
)
def test_shl(vm_class, val1, val2, expected):
    computation = prepare_general_computation(vm_class)
    computation.stack_push_bytes(decode_hex(val1))
    computation.stack_push_bytes(decode_hex(val2))
    computation.opcodes[opcode_values.SHL](computation)

    result = computation.stack_pop1_int()

    assert encode_hex(pad32(int_to_big_endian(result))) == expected


@pytest.mark.parametrize(
    # Cases: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-145.md#shr-logical-shift-right
    'vm_class, val1, val2, expected',
    (
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x00',
            '0x0000000000000000000000000000000000000000000000000000000000000001',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x01',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0x01',
            '0x4000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0xff',
            '0x0000000000000000000000000000000000000000000000000000000000000001',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0x0100',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0x0101',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x00',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x01',
            '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0xff',
            '0x0000000000000000000000000000000000000000000000000000000000000001',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x0100',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000000',
            '0x01',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
    )
)
def test_shr(vm_class, val1, val2, expected):
    computation = prepare_general_computation(vm_class)
    computation.stack_push_bytes(decode_hex(val1))
    computation.stack_push_bytes(decode_hex(val2))
    computation.opcodes[opcode_values.SHR](computation)

    result = computation.stack_pop1_int()
    assert encode_hex(pad32(int_to_big_endian(result))) == expected


@pytest.mark.parametrize(
    # EIP: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-145.md#sar-arithmetic-shift-right
    'vm_class, val1, val2, expected',
    (
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x00',
            '0x0000000000000000000000000000000000000000000000000000000000000001',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000001',
            '0x01',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0x01',
            '0xc000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0xff',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0x0100',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0x8000000000000000000000000000000000000000000000000000000000000000',
            '0x0101',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x00',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x01',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0xff',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x0100',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        (
            PhotonVM,
            '0x0000000000000000000000000000000000000000000000000000000000000000',
            '0x01',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),

        (
            PhotonVM,
            '0x4000000000000000000000000000000000000000000000000000000000000000',
            '0xfe',
            '0x0000000000000000000000000000000000000000000000000000000000000001',
        ),
        (
            PhotonVM,
            '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0xf8',
            '0x000000000000000000000000000000000000000000000000000000000000007f',
        ),
        (
            PhotonVM,
            '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0xfe',
            '0x0000000000000000000000000000000000000000000000000000000000000001',
        ),
        (
            PhotonVM,
            '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0xff',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0x0100',
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
    )
)
def test_sar(vm_class, val1, val2, expected):
    computation = prepare_general_computation(vm_class)
    computation.stack_push_bytes(decode_hex(val1))
    computation.stack_push_bytes(decode_hex(val2))
    computation.opcodes[opcode_values.SAR](computation)

    result = computation.stack_pop1_int()
    assert encode_hex(pad32(int_to_big_endian(result))) == expected


@pytest.mark.parametrize(
    'vm_class, address, expected',
    (
        (
            PhotonVM,
            ADDRESS_NOT_IN_STATE,
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            EMPTY_ADDRESS_IN_STATE,
            '0x0000000000000000000000000000000000000000000000000000000000000000',
        ),
        (
            PhotonVM,
            ADDRESS_WITH_JUST_BALANCE,
            '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
        ),
        (
            PhotonVM,
            ADDRESS_WITH_CODE[0],
            # equivalent to encode_hex(keccak(ADDRESS_WITH_CODE[1])),
            '0xb6f5188e2984211a0de167a56a92d85bee084d7a469d97a59e1e2b573dbb4301'
        ),
    )
)
def test_extcodehash(vm_class, address, expected):
    computation = prepare_general_computation(vm_class)

    computation.stack_push_bytes(decode_hex(address))
    computation.opcodes[opcode_values.EXTCODEHASH](computation)

    result = computation.stack_pop1_bytes()
    assert encode_hex(pad32(result)) == expected


@pytest.mark.parametrize(
    # Testcases from https://eips.ethereum.org/EIPS/eip-1283
    'vm_class, code, gas_used, refund, original',
    (

            #Istanbul re-adds the SSTORE change, but at a higher base cost (200->800)
            (
                    PhotonVM,
                    '0x60006000556000600055',
                    1612,
                    0,
                    0,
            ),
            (
                    PhotonVM,
                    '0x60006000556001600055',
                    20812,
                    0,
                    0,
            ),
            (
                    PhotonVM,
                    '0x60016000556000600055',
                    20812,
                    19200,
                    0,
            ),
            (
                    PhotonVM,
                    '0x60016000556002600055',
                    20812,
                    0,
                    0,
            ),
            (
                    PhotonVM,
                    '0x60016000556001600055',
                    20812,
                    0,
                    0,
            ),
            (
                    PhotonVM,
                    '0x60006000556000600055',
                    5812,
                    15000,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60006000556001600055',
                    5812,
                    4200,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60006000556002600055',
                    5812,
                    0,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60026000556000600055',
                    5812,
                    15000,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60026000556003600055',
                    5812,
                    0,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60026000556001600055',
                    5812,
                    4200,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60026000556002600055',
                    5812,
                    0,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60016000556000600055',
                    5812,
                    15000,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60016000556002600055',
                    5812,
                    0,
                    1,
            ),
            (
                    PhotonVM,
                    '0x60016000556001600055',
                    1612,
                    0,
                    1,
            ),
            (
                    PhotonVM,
                    '0x600160005560006000556001600055',
                    40818,
                    19200,
                    0,
            ),
            (
                    PhotonVM,
                    '0x600060005560016000556000600055',
                    10818,
                    19200,
                    1,
            ),
    )
)
def test_sstore(vm_class, code, gas_used, refund, original):

    computation = setup_computation(vm_class, CANONICAL_ADDRESS_B, decode_hex(code), is_receive=True, to=CANONICAL_ADDRESS_B)

    computation.state.account_db.set_balance(CANONICAL_ADDRESS_B, 100000000000)
    computation.state.account_db.set_storage(CANONICAL_ADDRESS_B, 0, original)
    assert computation.state.account_db.get_storage(CANONICAL_ADDRESS_B, 0) == original
    computation.state.account_db.persist()

    assert computation.state.account_db.get_storage(CANONICAL_ADDRESS_B, 0, from_journal=True) == original
    assert computation.state.account_db.get_storage(CANONICAL_ADDRESS_B, 0, from_journal=False) == original

    comp = computation.apply_message()
    assert comp.get_gas_refund() == refund
    assert comp.get_gas_used() == gas_used

    # Use external smart contract storage
    computation = setup_computation(vm_class,
                                    CANONICAL_ADDRESS_B,
                                    decode_hex(code),
                                    is_receive=True,
                                    to=CANONICAL_ADDRESS_B,
                                    is_surrogate=True,
                                    code_address = CANONICAL_ADDRESS_B)

    computation.state.account_db.set_external_smart_contract_storage(CANONICAL_ADDRESS_B, CANONICAL_ADDRESS_B, 0, original)
    assert computation.state.account_db.get_external_smart_contract_storage(CANONICAL_ADDRESS_B, CANONICAL_ADDRESS_B, 0) == original
    computation.state.account_db.persist()

    assert computation.state.account_db.get_external_smart_contract_storage(CANONICAL_ADDRESS_B, CANONICAL_ADDRESS_B, 0, from_journal=True) == original
    assert computation.state.account_db.get_external_smart_contract_storage(CANONICAL_ADDRESS_B, CANONICAL_ADDRESS_B, 0, from_journal=False) == original

    comp = computation.apply_message()
    assert comp.get_gas_refund() == refund
    assert comp.get_gas_used() == gas_used


@pytest.mark.parametrize(
    'gas_supplied, success, gas_used, refund',
    (
        # 2 pushes get executed before the SSTORE, so add 6 before checking the 2300 limit
        (2306, False, 2306, 0),
        # Just one more gas, leaving 2301 at the beginning of SSTORE, allows it to succeed
        (2307, True, 806, 0),
    )
)
def test_sstore_limit_2300(gas_supplied, success, gas_used, refund):
    vm_class = PhotonVM
    hex_code = '0x6000600055'
    original = 0
    computation = setup_computation(
        vm_class,
        CANONICAL_ADDRESS_B,
        decode_hex(hex_code),
        gas=gas_supplied,
        is_receive=True,
        to=CANONICAL_ADDRESS_B,
    )

    computation.state.account_db.set_balance(CANONICAL_ADDRESS_B, 100000000000)
    computation.state.account_db.set_storage(CANONICAL_ADDRESS_B, 0, original)
    assert computation.state.account_db.get_storage(CANONICAL_ADDRESS_B, 0) == original
    computation.state.account_db.persist()

    comp = computation.apply_message()
    if success and not comp.is_success:
        raise comp._error
    else:
        assert comp.is_success == success
    assert comp.get_gas_refund() == refund
    assert comp.get_gas_used() == gas_used


@pytest.mark.parametrize(
    # Testcases from https://eips.ethereum.org/EIPS/eip-1344
    'vm_class, chain_id, expected_result',
    (
        (
            PhotonVM,
            86,
            86,
        ),
        (
            PhotonVM,
            0,
            0,
        ),
        (
            PhotonVM,
            -1,
            ValidationError,
        ),
        (
            PhotonVM,
            2 ** 256 - 1,
            2 ** 256 - 1,
        ),
        (
            PhotonVM,
            2 ** 256,
            ValidationError,
        ),
    )
)
def test_chainid(vm_class, chain_id, expected_result):
    if not isinstance(expected_result, int):
        with pytest.raises(expected_result):
            computation = prepare_general_computation(vm_class, chain_id=chain_id)
        return

    computation = prepare_general_computation(vm_class, chain_id=chain_id)

    computation.opcodes[opcode_values.CHAINID](computation)
    result = computation.stack_pop1_any()

    assert result == expected_result


@pytest.mark.parametrize(
    'vm_class, code, expect_exception, expect_gas_used',
    (
        (
            PhotonVM,
            assemble(
                opcode_values.PUSH20,
                CANONICAL_ADDRESS_B,
                opcode_values.BALANCE,
            ),
            None,
            3 + 700,  # balance now costs more
        ),
        (
            PhotonVM,
            assemble(
                opcode_values.SELFBALANCE,
            ),
            None,
            5,
        ),
    )
)
def test_balance(vm_class, code, expect_exception, expect_gas_used):
    sender_balance = 987654321
    computation = setup_computation(vm_class, CANONICAL_ADDRESS_B, code, is_receive=True, to=CANONICAL_ADDRESS_B)

    # make sure setup is correct
    assert computation.msg.sender == CANONICAL_ADDRESS_B

    computation.state.account_db.set_balance(CANONICAL_ADDRESS_B, sender_balance)
    computation.state.account_db.persist()

    comp = computation.apply_message()
    if expect_exception:
        assert isinstance(comp.error, expect_exception)
    else:
        assert comp.is_success
        assert comp.stack_pop1_int() == sender_balance

    assert len(comp._stack) == 0
    assert comp.get_gas_used() == expect_gas_used


@pytest.mark.parametrize(
    'vm_class, code, expect_gas_used',
    (
        (
            PhotonVM,
            assemble(
                opcode_values.PUSH1,
                0x0,
                opcode_values.SLOAD,
            ),
            3 + 800,
        ),
        (
            PhotonVM,
            assemble(
                opcode_values.PUSH20,
                CANONICAL_ADDRESS_A,
                opcode_values.EXTCODEHASH,
            ),
            3 + 700,
        ),
    )
)
def test_gas_costs(vm_class, code, expect_gas_used):
    computation = setup_computation(vm_class, CANONICAL_ADDRESS_B, code, is_receive=True, to=CANONICAL_ADDRESS_B)
    comp = computation.apply_message()
    assert comp.is_success
    assert comp.get_gas_used() == expect_gas_used


@pytest.mark.parametrize(
    'vm_class, input_hex, output_hex, expect_exception',
    (
        (
            PhotonVM,
            "",
            "",
            VMError,
        ),
        (
            PhotonVM,
            "00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",  # noqa: E501
            "",
            VMError,
        ),
        (
            PhotonVM,
            "000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",  # noqa: E501
            "",
            VMError,
        ),
        (
            PhotonVM,
            "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002",  # noqa: E501
            "",
            VMError,
        ),
        (
            PhotonVM,
            "0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",  # noqa: E501
            "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b",  # noqa: E501
            None,
        ),
        (
            PhotonVM,
            "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",  # noqa: E501
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",  # noqa: E501
            None,
        ),
        (
            PhotonVM,
            "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000",  # noqa: E501
            "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735",  # noqa: E501
            None,
        ),
        (
            PhotonVM,
            "0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",  # noqa: E501
            "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421",  # noqa: E501
            None,
        ),
        pytest.param(
            PhotonVM,
            "ffffffff48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",  # noqa: E501
            "fc59093aafa9ab43daae0e914c57635c5402d8e3d2130eb9b3cc181de7f0ecf9b22bf99a7815ce16419e200e01846e6b5df8cc7703041bbceb571de6631d2615",  # noqa: E501
            None,
            marks=pytest.mark.skip(reason="Takes 90s to run against blake2b-py v0.1.2, but passes!")
        ),
    )
)
def test_blake2b_f_compression(vm_class, input_hex, output_hex, expect_exception):
    computation = setup_computation(
        vm_class,
        CANONICAL_ADDRESS_B,
        code=b'',
        gas=2**32 - 1,
        to=force_bytes_to_address(b'\x09'),
        data=to_bytes(hexstr=input_hex),
        is_receive=True
    )

    comp = computation.apply_message()
    if expect_exception:
        assert isinstance(comp.error, expect_exception)
    else:
        comp.raise_if_error()
        result = comp.output
        assert result.hex() == output_hex


@pytest.mark.parametrize(
    'vm_class, tx_gas, call_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error',
    (
        ( # not enough gas in transaction
            PhotonVM,
            1000,
            200000,
            0,
            True,
            False,
            False,
            False,
            False,
            OutOfGas
        ),
        ( # enough tx gas, but not enough call gas
            PhotonVM,
            10000000,
            2000,
            0,
            True,
            False,
            False,
            False,
            False,
            OutOfGas
        ),
        (
            PhotonVM,
            100000000,
            100000,
            0,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        (
            PhotonVM,
            100000000,
            100000,
            1,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        ( # surrogate calls cannot create children calls
            PhotonVM,
            100000000,
            100000,
            0,
            True,
            True,
            False,
            False,
            False,
            ForbiddenOperationForSurrogateCall
        ),
        ( # Execute on send cannot create calls
            PhotonVM,
            100000000,
            100000,
            0,
            False,
            False,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (  # Execute on send cannot create calls
            PhotonVM,
            100000000,
            100000,
            0,
            False,
            True,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (
            PhotonVM,
            100000000,
            100000,
            1,
            True,
            False,
            True,
            False,
            False,
            None
        ),
        ( # create_tx will execute to determine gas usage, but it wont save any external calls
            PhotonVM,
            100000000,
            100000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            True, # is_create_tx
            False, # execute_on_send
            None
        ),
        ( # execute on send but not create
            PhotonVM,
            100000000,
            100000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            False, # is_create_tx
            True, # execute_on_send
            ForbiddenOperationForExecutingOnSend
        ),

    )
)
def test_call(vm_class, tx_gas, call_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error):
    call_data = encode_hex(pad32(b"1283712983711973"))
    code = assemble(
                # store call_data into memory
                opcode_values.PUSH32,
                call_data, # value
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # start position
                opcode_values.MSTORE,

                #store call parameters in stack
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # memory_out_length
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))),# memory_out_start
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(32))),# memory_in_length
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))),# memory_in_start
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(value))), # value
                opcode_values.PUSH20,
                CANONICAL_ADDRESS_A, # to
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(call_gas))), # gas

                # make the call
                opcode_values.CALL, # call
            )

    if is_create_tx:
        create_address = CANONICAL_ADDRESS_B
        to = CREATE_CONTRACT_ADDRESS
    else:
        create_address = None
        to = CANONICAL_ADDRESS_B

    computation = setup_computation(
        vm_class,
        create_address,
        code=code,
        gas=tx_gas,
        to=to,
        data=b'',
        is_receive=is_receive,
        is_surrogate=is_surrogate,
        code_address=CANONICAL_ADDRESS_B,
        is_computation_call_origin=computation_call_origin,
        execute_on_send = execute_on_send,
    )

    computation.state.account_db.set_balance(CANONICAL_ADDRESS_B, value)

    if value > 0:
        expected_call_gas = call_gas + GAS_CALLSTIPEND
    else:
        expected_call_gas = call_gas

    comp = computation.apply_message()
    external_call_messages = comp.get_all_children_external_call_messages()

    if expect_error is not None:
        assert isinstance(comp.error, expect_error)
        assert(len(external_call_messages) == 0)
    else:
        with pytest.raises(AttributeError):
            error = comp.error

        if is_create_tx and not is_receive:
            assert(len(external_call_messages) == 0)
        else:
            call_message = external_call_messages[0]
            assert (call_message.gas == expected_call_gas)
            assert (call_message.to == CANONICAL_ADDRESS_A)
            assert (call_message.sender == CANONICAL_ADDRESS_B)
            assert (call_message.value == value)
            assert (call_message.data_as_bytes == decode_hex(call_data))
            assert (call_message.code == b'')
            assert (call_message.create_address is None)
            assert (call_message.code_address == call_message.to)
            assert (call_message.should_transfer_value == True)
            assert (call_message.is_static == False)
            assert (call_message.refund_amount == 0)
            assert (call_message.execute_on_send == False)
            assert (call_message.nonce == 0)

            assert (call_message.resolved_to == call_message.to)
            assert (call_message.is_create == False)
            assert (call_message.child_tx_code_address == b'')
            assert (call_message.child_tx_create_address == b'')

            assert (comp.transaction_context.child_tx_origin == CANONICAL_ADDRESS_C if computation_call_origin else call_message.sender)
            assert (comp.transaction_context.is_computation_call_origin == computation_call_origin)
            assert (comp.transaction_context.is_surrogate_call == is_surrogate)

            # pprint("gas: {} | to: {} | sender: {} | value: {} | data: {} | code: {} | depth: {} | create_address: {} | code_address: {} | should_transfer_value: {} | is_static: {} | refund_amount: {} | execute_on_send: {} | nonce: {}".format(
            #         call_message.gas,
            #         call_message.to,
            #         call_message.sender,
            #         call_message.value,
            #         call_message.data,
            #         call_message.code,
            #         call_message.depth,
            #         call_message.create_address,
            #         call_message.code_address,
            #         call_message.should_transfer_value,
            #         call_message.is_static,
            #         call_message.refund_amount,
            #         call_message.execute_on_send,
            #         call_message.nonce
            #         )
            # )


@pytest.mark.parametrize(
    'vm_class, tx_gas, call_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error',
    (
        ( # not enough gas in transaction
            PhotonVM,
            1000,
            200000,
            0,
            True,
            False,
            False,
            False,
            False,
            OutOfGas
        ),
        ( # enough tx gas, but not enough call gas
            PhotonVM,
            10000000,
            2000,
            0,
            True,
            False,
            False,
            False,
            False,
            OutOfGas
        ),
        (
            PhotonVM,
            100000000,
            100000,
            0,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        (
            PhotonVM,
            100000000,
            100000,
            1,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        ( # surrogate calls cannot create children calls
            PhotonVM,
            100000000,
            100000,
            0,
            True,
            True,
            False,
            False,
            False,
            ForbiddenOperationForSurrogateCall
        ),
        ( # Execute on send cannot create calls
            PhotonVM,
            100000000,
            100000,
            0,
            False,
            False,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (  # Execute on send cannot create calls
            PhotonVM,
            100000000,
            100000,
            0,
            False,
            True,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (
            PhotonVM,
            100000000,
            100000,
            1,
            True,
            False,
            True,
            False,
            False,
            None
        ),
        ( # create_tx will execute to determine gas usage, but it wont save any external calls
            PhotonVM,
            100000000,
            100000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            True, # is_create_tx
            False, # execute_on_send
            None
        ),
        ( # execute on send but not create
            PhotonVM,
            100000000,
            100000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            False, # is_create_tx
            True, # execute_on_send
            ForbiddenOperationForExecutingOnSend
        ),

    )
)
def test_surrogate_call(vm_class, tx_gas, call_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error):
    call_data = encode_hex(pad32(b"1283712983711973"))
    code = assemble(
                # store call_data into memory
                opcode_values.PUSH32,
                call_data, # value
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # start position
                opcode_values.MSTORE,

                #store call parameters in stack
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(32))), # memory_in_length
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # memory_in_start
                opcode_values.PUSH20,
                CANONICAL_ADDRESS_A,  # to
                opcode_values.PUSH1,
                encode_hex(int_to_big_endian(1 if execute_on_send else 0)), # execute on send
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(value))), # value
                opcode_values.PUSH20,
                CANONICAL_ADDRESS_D, # code_address
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(call_gas))), # gas

                # make the call
                opcode_values.SURROGATECALL, # call
            )

    if is_create_tx:
        create_address = CANONICAL_ADDRESS_B
        to = CREATE_CONTRACT_ADDRESS
    else:
        create_address = None
        to = CANONICAL_ADDRESS_B

    computation = setup_computation(
        vm_class,
        create_address,
        code=code,
        gas=tx_gas,
        to=to,
        data=b'',
        is_receive=is_receive,
        is_surrogate=is_surrogate,
        code_address=CANONICAL_ADDRESS_B,
        is_computation_call_origin=computation_call_origin,
        execute_on_send=execute_on_send,
    )
    computation.state.account_db.set_balance(CANONICAL_ADDRESS_B, value)

    if value > 0:
        expected_call_gas = call_gas + GAS_CALLSTIPEND
    else:
        expected_call_gas = call_gas

    comp = computation.apply_message()
    external_call_messages = comp.get_all_children_external_call_messages()

    if expect_error is not None:
        assert isinstance(comp.error, expect_error)
        assert (len(external_call_messages) == 0)
    else:
        with pytest.raises(AttributeError):
            error = comp.error

        if is_create_tx and not is_receive:
            assert(len(external_call_messages) == 0)
        else:

            call_message = external_call_messages[0]
            assert (call_message.gas == expected_call_gas)
            assert (call_message.to == CANONICAL_ADDRESS_A)
            assert (call_message.sender == CANONICAL_ADDRESS_B)
            assert (call_message.value == value)
            assert (call_message.data_as_bytes == decode_hex(call_data))
            assert (call_message.code == b'')
            assert (call_message.create_address is None)
            assert (call_message.code_address == CANONICAL_ADDRESS_D)
            assert (call_message.should_transfer_value == True)
            assert (call_message.is_static == False)
            assert (call_message.refund_amount == 0)
            assert (call_message.execute_on_send == execute_on_send)
            assert (call_message.nonce == 0)

            assert (call_message.resolved_to == call_message.to)
            assert (call_message.is_create == False)
            assert (call_message.child_tx_code_address == CANONICAL_ADDRESS_D)
            assert (call_message.child_tx_create_address == b'')

            assert (comp.transaction_context.child_tx_origin == CANONICAL_ADDRESS_C if computation_call_origin else call_message.sender)
            assert (comp.transaction_context.is_computation_call_origin == computation_call_origin)
            assert (comp.transaction_context.is_surrogate_call == is_surrogate)


@pytest.mark.parametrize(
    'vm_class, tx_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error',
    (
        ( # not enough gas in transaction
            PhotonVM,
            1000,
            0,
            True,
            False,
            False,
            False,
            False,
            OutOfGas
        ),
        (
            PhotonVM,
            100000000,
            0,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        (
            PhotonVM,
            100000000,
            1,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        ( # surrogate calls cannot create children calls
            PhotonVM,
            100000000,
            0,
            True,
            True,
            False,
            False,
            False,
            ForbiddenOperationForSurrogateCall
        ),
        ( # Execute on send cannot create calls
            PhotonVM,
            100000000,
            0,
            False,
            False,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (  # Execute on send cannot create calls
            PhotonVM,
            100000000,
            0,
            False,
            True,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (
            PhotonVM,
            100000000,
            1,
            True,
            False,
            True,
            False,
            False,
            None
        ),
        ( # create_tx will execute to determine gas usage, but it wont save any external calls
            PhotonVM,
            100000000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            True, # is_create_tx
            False, # execute_on_send
            None
        ),
        ( # execute on send but not create
            PhotonVM,
            100000000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            False, # is_create_tx
            True, # execute_on_send
            ForbiddenOperationForExecutingOnSend
        ),

    )
)
def test_create_call(vm_class, tx_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error):
    call_data = encode_hex(pad32(b"1283712983711973"))
    code = assemble(
        # store call_data into memory
        opcode_values.PUSH32,
        call_data,  # value
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # start position
        opcode_values.MSTORE,

        # store call parameters in stack
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(32))),  # memory_in_length
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # memory_in_start
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(value))),  # value

        # make the call
        opcode_values.CREATE,  # create
    )

    if is_create_tx:
        create_address = CANONICAL_ADDRESS_B
        to = CREATE_CONTRACT_ADDRESS
    else:
        create_address = None
        to = CANONICAL_ADDRESS_B

    computation = setup_computation(
        vm_class,
        create_address,
        code=code,
        gas=tx_gas,
        to=to,
        data=b'',
        is_receive=is_receive,
        is_surrogate=is_surrogate,
        code_address=CANONICAL_ADDRESS_B,
        is_computation_call_origin=computation_call_origin,
        execute_on_send=execute_on_send,
    )
    computation.state.account_db.set_balance(CANONICAL_ADDRESS_B, value)

    computation_call_nonce = computation.state.execution_context.computation_call_nonce
    expected_contract_address = generate_contract_address(
        computation.transaction_context.this_chain_address,
        computation_call_nonce,
    )

    comp = computation.apply_message()
    external_call_messages = comp.get_all_children_external_call_messages()

    if expect_error is not None:
        assert isinstance(comp.error, expect_error)
        assert (len(external_call_messages) == 0)
    else:
        with pytest.raises(AttributeError):
            error = comp.error

        if is_create_tx and not is_receive:
            assert (len(external_call_messages) == 0)
        else:

            call_message = external_call_messages[0]
            assert (call_message.to == CREATE_CONTRACT_ADDRESS)
            assert (call_message.sender == CANONICAL_ADDRESS_B)
            assert (call_message.value == value)
            assert (call_message.data_as_bytes == decode_hex(call_data))
            assert (call_message.code == b'')
            assert (call_message.create_address == expected_contract_address)
            assert (call_message.code_address == b'')
            assert (call_message.should_transfer_value == True)
            assert (call_message.is_static == False)
            assert (call_message.refund_amount == 0)
            assert (call_message.execute_on_send == False)
            assert (call_message.nonce == 0)

            assert (call_message.resolved_to == expected_contract_address)
            assert (call_message.is_create == True)
            assert (call_message.child_tx_code_address == b'')
            assert (call_message.child_tx_create_address == expected_contract_address)

            assert (comp.transaction_context.child_tx_origin == CANONICAL_ADDRESS_C if computation_call_origin else call_message.sender)
            assert (comp.transaction_context.is_computation_call_origin == computation_call_origin)
            assert (comp.transaction_context.is_surrogate_call == is_surrogate)



@pytest.mark.parametrize(
    'vm_class, tx_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error',
    (
        ( # not enough gas in transaction
            PhotonVM,
            1000,
            0,
            True,
            False,
            False,
            False,
            False,
            OutOfGas
        ),
        (
            PhotonVM,
            100000000,
            0,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        (
            PhotonVM,
            100000000,
            1,
            True,
            False,
            False,
            False,
            False,
            None
        ),
        ( # surrogate calls cannot create children calls
            PhotonVM,
            100000000,
            0,
            True,
            True,
            False,
            False,
            False,
            ForbiddenOperationForSurrogateCall
        ),
        ( # Execute on send cannot create calls
            PhotonVM,
            100000000,
            0,
            False,
            False,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (  # Execute on send cannot create calls
            PhotonVM,
            100000000,
            0,
            False,
            True,
            False,
            False,
            True,
            ForbiddenOperationForExecutingOnSend
        ),
        (
            PhotonVM,
            100000000,
            1,
            True,
            False,
            True,
            False,
            False,
            None
        ),
        ( # create_tx will execute to determine gas usage, but it wont save any external calls
            PhotonVM,
            100000000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            True, # is_create_tx
            False, # execute_on_send
            None
        ),
        ( # execute on send but not create
            PhotonVM,
            100000000,
            0,
            False, # is_receive
            False, # is_surrogate
            False, # computation_call_origin
            False, # is_create_tx
            True, # execute_on_send
            ForbiddenOperationForExecutingOnSend
        ),

    )
)
def test_create2_call(vm_class, tx_gas, value, is_receive, is_surrogate, computation_call_origin, is_create_tx, execute_on_send, expect_error):
    call_data = encode_hex(pad32(b"1283712983711973"))
    salt = encode_hex(pad32(int_to_big_endian(1337)))
    code = assemble(
        # store call_data into memory
        opcode_values.PUSH32,
        call_data,  # value
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # start position
        opcode_values.MSTORE,

        # store call parameters in stack
        opcode_values.PUSH32,
        salt,  # salt
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(32))),  # memory_in_length
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # memory_in_start
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(value))),  # value

        # make the call
        opcode_values.CREATE2,  # create
    )

    if is_create_tx:
        create_address = CANONICAL_ADDRESS_B
        to = CREATE_CONTRACT_ADDRESS
    else:
        create_address = None
        to = CANONICAL_ADDRESS_B

    computation = setup_computation(
        vm_class,
        create_address,
        code=code,
        gas=tx_gas,
        to=to,
        data=b'',
        is_receive=is_receive,
        is_surrogate=is_surrogate,
        code_address=CANONICAL_ADDRESS_B,
        is_computation_call_origin=computation_call_origin,
        execute_on_send=execute_on_send,
    )
    computation.state.account_db.set_balance(CANONICAL_ADDRESS_B, value)

    expected_contract_address = generate_safe_contract_address(
        computation.transaction_context.this_chain_address,
        1337,
        decode_hex(call_data)
    )

    comp = computation.apply_message()
    external_call_messages = comp.get_all_children_external_call_messages()

    if expect_error is not None:
        assert isinstance(comp.error, expect_error)
        assert (len(external_call_messages) == 0)
    else:
        with pytest.raises(AttributeError):
            error = comp.error

        if is_create_tx and not is_receive:
            assert (len(external_call_messages) == 0)
        else:

            call_message = external_call_messages[0]
            assert (call_message.to == CREATE_CONTRACT_ADDRESS)
            assert (call_message.sender == CANONICAL_ADDRESS_B)
            assert (call_message.value == value)
            assert (call_message.data_as_bytes == decode_hex(call_data))
            assert (call_message.code == b'')
            assert (call_message.create_address == expected_contract_address)
            assert (call_message.code_address == b'')
            assert (call_message.should_transfer_value == True)
            assert (call_message.is_static == False)
            assert (call_message.refund_amount == 0)
            assert (call_message.execute_on_send == False)
            assert (call_message.nonce == 0)

            assert (call_message.resolved_to == expected_contract_address)
            assert (call_message.is_create == True)
            assert (call_message.child_tx_code_address == b'')
            assert (call_message.child_tx_create_address == expected_contract_address)

            assert (comp.transaction_context.child_tx_origin == CANONICAL_ADDRESS_C if computation_call_origin else call_message.sender)
            assert (comp.transaction_context.is_computation_call_origin == computation_call_origin)
            assert (comp.transaction_context.is_surrogate_call == is_surrogate)