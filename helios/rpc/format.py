import functools
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Union,
    Tuple,
)
from cytoolz import (
    compose,
    merge,
)
from eth_typing import Hash32

from eth_utils import (
    apply_formatters_to_dict,
    decode_hex,
    encode_hex,
    int_to_big_endian,
    to_hex,
)

import rlp_cython as rlp

from helios.chains.coro import (
    AsyncChain
)
from hvm.constants import (
    CREATE_CONTRACT_ADDRESS)
from hvm.exceptions import TransactionNotFound
from hvm.rlp.blocks import (
    BaseBlock
)
from hvm.rlp.consensus import StakeRewardBundle
from hvm.rlp.headers import (
    BlockHeader
)
from hvm.rlp.receipts import Receipt
from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction
)
from hvm.utils.address import generate_contract_address


def underscore_to_camel_case(input_string:str) -> str:
    if isinstance(input_string,str):
        pieces = input_string.split('_')
        camel_case_string = pieces[0]
        for i in range(1,len(pieces)):
            camel_case_string += pieces[i].capitalize()
        return camel_case_string
    else:
        return ''

def all_rlp_fields_to_dict_camel_case(rlp_object: Union[rlp.Serializable, List, Tuple]) -> Union[Dict[str, any], List[any]]:
    #It is either rlp.Serializable or a list
    if isinstance(rlp_object, rlp.Serializable):
        dict_to_return = {}
        # add all of the fields in camelcase
        for i in range(len(rlp_object._meta.field_names)):
            field_name = rlp_object._meta.field_names[i]
            key = underscore_to_camel_case(field_name)
            raw_val = getattr(rlp_object, field_name)
            if isinstance(raw_val, rlp.Serializable) or isinstance(raw_val, list) or isinstance(raw_val, tuple):
                val=all_rlp_fields_to_dict_camel_case(raw_val)
            else:
                val = to_hex(raw_val)

            dict_to_return[key] = val
        return dict_to_return
    else:
        list_to_return = []
        for i in range(len(rlp_object)):
            raw_val = rlp_object[i]
            if isinstance(raw_val, rlp.Serializable) or isinstance(raw_val, list) or isinstance(raw_val, tuple):
                val = all_rlp_fields_to_dict_camel_case(raw_val)
            else:
                val = to_hex(raw_val)
            list_to_return.append(val)
        return list_to_return


def receipt_to_dict(receipt: Receipt, tx_hash: Hash32, chain: AsyncChain) -> Dict[str, str]:
    dict_to_return = all_rlp_fields_to_dict_camel_case(receipt)

    block_hash, index, is_receive = chain.chaindb.get_transaction_index(tx_hash)
    dict_to_return['blockHash'] = to_hex(block_hash)
    dict_to_return['transactionHash'] = to_hex(tx_hash)
    dict_to_return['isReceive'] = to_hex(is_receive)
    dict_to_return['transactionIndex'] = to_hex(index)

    block_header = chain.get_block_header_by_hash(block_hash)
    dict_to_return['blockNumber'] = to_hex(block_header.block_number)

    transaction = chain.get_canonical_transaction(tx_hash)

    if is_receive:
        dict_to_return['to'] = to_hex(block_header.chain_address)
        dict_to_return['sender'] = to_hex(chain.chaindb.get_chain_wallet_address_for_block_hash(transaction.sender_block_hash))
    else:
        dict_to_return['to'] = to_hex(transaction.to)
        dict_to_return['sender'] = to_hex(transaction.sender)

        if transaction.to == CREATE_CONTRACT_ADDRESS:
            dict_to_return['contractAddress'] = to_hex(generate_contract_address(transaction.sender, transaction.nonce))

    dict_to_return['cumulativeGasUsed'] = to_hex(chain.chaindb.get_cumulative_gas_used(tx_hash))

    return dict_to_return

def transaction_to_dict(transaction: BaseTransaction, chain: AsyncChain) -> Dict[str, str]:
    dict_to_return = all_rlp_fields_to_dict_camel_case(transaction)
    dict_to_return['hash'] = encode_hex(transaction.hash)
    dict_to_return['gasUsed'] = to_hex(chain.chaindb.get_transaction_receipt(transaction.hash).gas_used)
    return dict_to_return



def transactions_to_dict(transactions: List[BaseTransaction],  chain: AsyncChain) -> List[Dict[str, str]]:
    dict_transactions = []
    for tx in transactions:
        dict_tx = transaction_to_dict(tx, chain)
        dict_transactions.append(dict_tx)

    return dict_transactions


def receive_transaction_to_dict(transaction: BaseReceiveTransaction, chain: AsyncChain) -> Dict[str, str]:
    dict_to_return = all_rlp_fields_to_dict_camel_case(transaction)
    dict_to_return['hash'] = encode_hex(transaction.hash)

    from_address = chain.get_block_header_by_hash(transaction.sender_block_hash).chain_address

    dict_to_return['from'] = to_hex(from_address)

    originating_transaction = chain.chaindb.get_transaction_by_hash(transaction.send_transaction_hash,
                                                             send_tx_class = chain.get_vm().get_transaction_class(),
                                                             receive_tx_class = chain.get_vm().get_receive_transaction_class())

    if transaction.is_refund:
        value = originating_transaction.remaining_refund
    else:
        value = originating_transaction.value

    dict_to_return['value'] = to_hex(value)
    dict_to_return['gasPrice'] = to_hex(originating_transaction.gas_price)

    try:
        dict_to_return['gasUsed'] = to_hex(chain.chaindb.get_transaction_receipt(transaction.hash).gas_used)
    except TransactionNotFound:
        dict_to_return['gasUsed'] = 0

    return dict_to_return



def receive_transactions_to_dict(transactions: List[BaseTransaction], chain: AsyncChain) -> List[Dict[str, str]]:
    dict_transactions = []
    for tx in transactions:
        dict_tx = receive_transaction_to_dict(tx, chain)
        dict_transactions.append(dict_tx)

    return dict_transactions


def reward_bundle_to_dict(reward_bundle: StakeRewardBundle) -> Dict[str, str]:
    dict_to_return = all_rlp_fields_to_dict_camel_case(reward_bundle)

    dict_to_return['hash'] = encode_hex(reward_bundle.hash)
    return dict_to_return




hexstr_to_int = functools.partial(int, base=16)


TRANSACTION_NORMALIZER = {
    'data': decode_hex,
    'from': decode_hex,
    'gas': hexstr_to_int,
    'gasPrice': hexstr_to_int,
    'nonce': hexstr_to_int,
    'to': decode_hex,
    'value': hexstr_to_int,
}

SAFE_TRANSACTION_DEFAULTS = {
    'data': b'',
    'to': CREATE_CONTRACT_ADDRESS,
    'value': 0,
}


def normalize_transaction_dict(transaction_dict: Dict[str, str]) -> Dict[str, Any]:
    normalized_dict = apply_formatters_to_dict(TRANSACTION_NORMALIZER, transaction_dict)
    return merge(SAFE_TRANSACTION_DEFAULTS, normalized_dict)


def header_to_dict(header: BlockHeader) -> Dict[str, str]:
    logs_bloom = encode_hex(int_to_big_endian(header.bloom))[2:]
    logs_bloom = '0x' + logs_bloom.rjust(512, '0')
    header_dict = {
        "chainAddress": encode_hex(header.chain_address),
        "extraData": encode_hex(header.extra_data),
        "gasLimit": hex(header.gas_limit),
        "gasUsed": hex(header.gas_used),
        "hash": encode_hex(header.hash),
        "logsBloom": logs_bloom,
        "number": hex(header.block_number),
        "parentHash": encode_hex(header.parent_hash),
        "rewardHash": encode_hex(header.parent_hash),
        "accountHash": encode_hex(header.account_hash),
        "receiptsRoot": encode_hex(header.receipt_root),
        "timestamp": hex(header.timestamp),
        "accountBalance": hex(header.account_balance),
        "transactionsRoot": encode_hex(header.transaction_root),
        "receiveTransactionsRoot": encode_hex(header.receive_transaction_root),
    }
    return header_dict


def block_to_dict(block: BaseBlock,
                  include_transactions: bool,
                  chain:AsyncChain) -> Dict[str, Union[str, List[str]]]:

    header_dict = header_to_dict(block.header)

    block_dict: Dict[str, Union[str, List[str]]] = dict(
        header_dict,
        size=hex(len(rlp.encode(block))),
    )

    if include_transactions:
        block_dict['transactions'] = transactions_to_dict(block.transactions, chain)
        block_dict['receiveTransactions'] = receive_transactions_to_dict(block.receive_transactions, chain)
        block_dict['rewardBundle'] = reward_bundle_to_dict(block.reward_bundle)
    else:
        block_dict['transactions'] = [encode_hex(tx.hash) for tx in block.transactions]
        block_dict['receiveTransactions'] = [encode_hex(tx.hash) for tx in block.receive_transactions]
        block_dict['rewardBundle'] = []

    return block_dict


def format_params(*formatters: Any) -> Callable[..., Any]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def formatted_func(self: Any, *args: Any) -> Callable[..., Any]:
            if len(formatters) != len(args):
                raise TypeError("could not apply %d formatters to %r, %r" % (len(formatters), args, formatters))
            formatted = (formatter(arg) for formatter, arg in zip(formatters, args))
            return await func(self, *formatted)
        return formatted_func
    return decorator


def to_int_if_hex(value: Any) -> Any:
    if isinstance(value, str) and value.startswith('0x'):
        return int(value, 16)
    else:
        return value


def empty_to_0x(val: str) -> str:
    if val:
        return val
    else:
        return '0x'


remove_leading_zeros = compose(hex, functools.partial(int, base=16))
