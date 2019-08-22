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
from hvm.utils.hexadecimal import pad_hex
from helios.chains.coro import (
    AsyncChain
)
from helios.protocol.common.datastructures import ConnectedNodesInfo
from hvm.constants import (
    CREATE_CONTRACT_ADDRESS)
from hvm.exceptions import TransactionNotFound
from hvm.rlp.blocks import (
    BaseBlock
)
from hvm.rlp.consensus import StakeRewardBundle, StakeRewardType2
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

def dict_keys_underscore_to_camel_case(input_dict):
    output_dict = {}
    for key, val in input_dict.items():
        key = underscore_to_camel_case(key)
        if isinstance(val, dict) or isinstance(val, list):
            output_dict[key] = dict_keys_underscore_to_camel_case(val)
        else:
            output_dict[key] = val

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

def connected_nodes_to_dict(connected_nodes_info: ConnectedNodesInfo) -> List[Dict[str, str]]:
    connected_nodes = connected_nodes_info.connected_nodes
    output_list = []
    for connected_node in connected_nodes:
        connected_node_dict = {}

        connected_node_dict['url'] = to_hex(text = connected_node['url'])
        connected_node_dict['ipAddress'] = to_hex(text = connected_node['ip_address'])
        connected_node_dict['udpPort'] = to_hex(connected_node['udp_port'])
        connected_node_dict['tcpPort'] = to_hex(connected_node['tcp_port'])
        connected_node_dict['stake'] = to_hex(connected_node['stake'])
        connected_node_dict['requestsSent'] = to_hex(connected_node['requests_sent'])
        connected_node_dict['failedRequests'] = to_hex(connected_node['failed_requests'])
        connected_node_dict['averageResponseTime'] = to_hex(connected_node['average_response_time'])

        output_list.append(connected_node_dict)
    return output_list


def receipt_to_dict(receipt: Receipt, tx_hash: Hash32, chain: AsyncChain) -> Dict[str, str]:
    dict_to_return = all_rlp_fields_to_dict_camel_case(receipt)

    block_hash, index, is_receive = chain.chaindb.get_transaction_index(tx_hash)

    dict_to_return['blockHash'] = to_hex(block_hash)
    dict_to_return['transactionHash'] = to_hex(tx_hash)
    dict_to_return['isReceive'] = to_hex(is_receive)
    dict_to_return['transactionIndex'] = to_hex(index)

    block_header = chain.get_block_header_by_hash(block_hash)
    dict_to_return['blockNumber'] = to_hex(block_header.block_number)

    for i in range(len(dict_to_return['logs'])):
        dict_to_return['logs'][i]['logIndex'] = to_hex(i)
        dict_to_return['logs'][i]['transactionIndex'] = to_hex(index)
        dict_to_return['logs'][i]['transactionHash'] = to_hex(tx_hash)
        dict_to_return['logs'][i]['blockHash'] = to_hex(block_hash)
        dict_to_return['logs'][i]['blockNumber'] = to_hex(block_header.block_number)
        dict_to_return['logs'][i]['topics'] = [pad_hex(value, 32) for value in dict_to_return['logs'][i]['topics']]

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
    transaction_hash = Hash32(transaction.hash)
    dict_to_return = all_rlp_fields_to_dict_camel_case(transaction)
    dict_to_return['from'] = encode_hex(transaction.sender)
    dict_to_return['hash'] = encode_hex(transaction.hash)
    dict_to_return['gasUsed'] = to_hex(chain.chaindb.get_transaction_receipt(transaction_hash).gas_used)
    block_hash, tx_index, is_receive = chain.chaindb.get_transaction_index(transaction_hash)
    dict_to_return['blockHash'] = encode_hex(block_hash)
    block_header = chain.chaindb.get_block_header_by_hash(block_hash)
    dict_to_return['blockNumber'] = to_hex(block_header.block_number)
    dict_to_return['transactionIndex'] = to_hex(tx_index)
    dict_to_return['input'] = encode_hex(transaction.data)
    dict_to_return['isReceive'] = to_hex(False)
    return dict_to_return



def transactions_to_dict(transactions: List[BaseTransaction],  chain: AsyncChain) -> List[Dict[str, str]]:
    dict_transactions = []
    for tx in transactions:
        dict_tx = transaction_to_dict(tx, chain)
        dict_transactions.append(dict_tx)

    return dict_transactions


def receive_transaction_to_dict(transaction: BaseReceiveTransaction, chain: AsyncChain) -> Dict[str, str]:
    tx_hash = transaction.hash
    dict_to_return = all_rlp_fields_to_dict_camel_case(transaction)
    dict_to_return['isReceive'] = to_hex(True)
    dict_to_return['hash'] = encode_hex(tx_hash)

    from_address = chain.get_block_header_by_hash(transaction.sender_block_hash).chain_address

    dict_to_return['from'] = to_hex(from_address)

    originating_transaction = chain.get_canonical_transaction(transaction.send_transaction_hash)

    if transaction.is_refund:
        send_transaction = chain.get_canonical_transaction(originating_transaction.send_transaction_hash)
        value = originating_transaction.remaining_refund
        to = send_transaction.sender
    else:
        send_transaction = originating_transaction
        value = originating_transaction.value
        to = send_transaction.to


    dict_to_return['value'] = to_hex(value)
    dict_to_return['gasPrice'] = to_hex(send_transaction.gas_price)
    dict_to_return['to'] = to_hex(to)
    try:
        dict_to_return['gasUsed'] = to_hex(chain.chaindb.get_transaction_receipt(transaction.hash).gas_used)
    except TransactionNotFound:
        dict_to_return['gasUsed'] = to_hex(0)

    try:
        block_hash, receive_tx_index, _ = chain.chaindb.get_transaction_index(tx_hash)
        num_send_transactions = chain.chaindb.get_number_of_send_tx_in_block(block_hash)
        block_tx_index = num_send_transactions + receive_tx_index
        dict_to_return['transactionIndex'] = to_hex(block_tx_index)
        dict_to_return['blockHash'] = to_hex(block_hash)
    except TransactionNotFound:
        pass

    return dict_to_return



def receive_transactions_to_dict(transactions: List[BaseTransaction], chain: AsyncChain) -> List[Dict[str, str]]:
    dict_transactions = []
    for tx in transactions:
        dict_tx = receive_transaction_to_dict(tx, chain)
        dict_transactions.append(dict_tx)

    return dict_transactions

def reward_type_2_to_dict(reward_type_2: StakeRewardType2) -> Dict[str, str]:
    dict_to_return = {}
    dict_to_return['amount'] = to_hex(reward_type_2.amount)

    dict_to_return['proof'] = []

    for proof in reward_type_2.proof:
        proof_dict = all_rlp_fields_to_dict_camel_case(proof)
        proof_dict['sender'] = to_hex(proof.sender)
        dict_to_return['proof'].append(proof_dict)

    return dict_to_return

def reward_bundle_to_dict(reward_bundle: StakeRewardBundle) -> Dict[str, str]:
    dict_to_return = {}
    dict_to_return['rewardType1'] = all_rlp_fields_to_dict_camel_case(reward_bundle.reward_type_1)
    dict_to_return['rewardType2'] = reward_type_2_to_dict(reward_bundle.reward_type_2)
    dict_to_return['hash'] = encode_hex(reward_bundle.hash)
    dict_to_return['isReward'] = to_hex(True)
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
        "sender": encode_hex(header.sender),
        "extraData": encode_hex(header.extra_data),
        "gasLimit": hex(header.gas_limit),
        "gasUsed": hex(header.gas_used),
        "hash": encode_hex(header.hash),
        "logsBloom": logs_bloom,
        "number": hex(header.block_number),
        "parentHash": encode_hex(header.parent_hash),
        "rewardHash": encode_hex(header.reward_hash),
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
        block_dict['rewardBundle'] = reward_bundle_to_dict(block.reward_bundle)
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

def dummy(value: Any):
    return value

def empty_to_0x(val: str) -> str:
    if val:
        return val
    else:
        return '0x'

def decode_hex_if_str(value: Any) -> Any:
    if isinstance(value, str) and value.startswith('0x'):
        return decode_hex(value)
    else:
        return value


remove_leading_zeros = compose(hex, functools.partial(int, base=16))
