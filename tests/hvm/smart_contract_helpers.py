import os
from hvm import TestnetChain
from hvm.chains.testnet import (
    TESTNET_GENESIS_PRIVATE_KEY,
)

from eth_utils import (
    decode_hex,
)

from solc import compile_files, get_solc_version

from pathlib import Path

home = str(Path.home())

# os.environ["SOLC_BINARY"] = home + "/.py-solc/solc-v0.4.25/bin/solc"
os.environ["SOLC_BINARY"] = home + "/solidity/cmake-build-debug/solc/solc"

try:
    get_solc_version()
except Exception:
    print("Solc not found. Installing")
    from solc import install_solc
    install_solc('v0.4.25')


from helios_web3 import HeliosWeb3 as Web3

import pickle

from tests.integration_test_helpers import W3_TX_DEFAULTS

from hvm.constants import CREATE_CONTRACT_ADDRESS

from rlp_cython.sedes.big_endian_int import BigEndianInt
from eth_utils import to_int

CONTRACT_DIR_NAME = Path('contract_data')

def compile_sol_and_save_to_file(solidity_file, output_file):
    compiled_sol = compile_files([solidity_file])
    print("writing compiled code dictionary with keys {}".format(compiled_sol.keys()))
    f = open(output_file, "wb")
    pickle.dump(compiled_sol, f)
    f.close()

def load_compiled_sol_dict(compiled_file_location):
    pickle_in = open(compiled_file_location, "rb")
    compiled_sol_dict = pickle.load(pickle_in)
    return compiled_sol_dict

def compile_and_get_contract_interface(base_filename:str, contract_name: str):
    base_filename_path = Path(base_filename)
    solidity_file =  CONTRACT_DIR_NAME / base_filename_path.with_suffix('.sol')
    compiled_sol_file = CONTRACT_DIR_NAME / base_filename_path.with_suffix('.pkl')

    compile_sol_and_save_to_file(solidity_file, compiled_sol_file)
    compiled_sol = load_compiled_sol_dict(compiled_sol_file)
    contract_interface = compiled_sol['{}:{}'.format(solidity_file, contract_name)]

    return contract_interface

def format_receipt_for_web3_to_extract_events(receipt, tx_hash, chain):
    def hex_to_32_bit_int_bytes(hex_val):
        sede = BigEndianInt(32)
        return sede.serialize(to_int(hexstr = hex_val))

    from helios.rpc.format import receipt_to_dict
    receipt_dict = receipt_to_dict(receipt, tx_hash, chain)
    for i in range(len(receipt_dict['logs'])):
        receipt_dict['logs'][i]['data'] = decode_hex(receipt_dict['logs'][i]['data'])

        receipt_dict['logs'][i]['topics'] = list(map(hex_to_32_bit_int_bytes, receipt_dict['logs'][i]['topics']))
    return receipt_dict

def import_all_pending_smart_contract_blocks(database):
    chain = TestnetChain(database, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                         TESTNET_GENESIS_PRIVATE_KEY)

    # now we need to add the block to the smart contract
    list_of_smart_contracts = chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
    for airdrop_contract_address in list_of_smart_contracts:
        chain = TestnetChain(database, airdrop_contract_address, TESTNET_GENESIS_PRIVATE_KEY)

        chain.populate_queue_block_with_receive_tx()
        chain.import_current_queue_block()
    return list_of_smart_contracts


def deploy_contract(db, base_filename:str, contract_name: str):
    contract_interface = compile_and_get_contract_interface(base_filename, contract_name)

    # deploy the contract
    w3 = Web3()

    HeliosDelegatedToken = w3.hls.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )

    # Build transaction to deploy the contract
    w3_tx1 = HeliosDelegatedToken.constructor().buildTransaction(W3_TX_DEFAULTS)

    chain = TestnetChain(db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=20000000,
        to=CREATE_CONTRACT_ADDRESS,
        value=0,
        data=decode_hex(w3_tx1['data'])
    )

    print("deploying smart contract")

    chain.import_current_queue_block()

    list_of_smart_contracts = import_all_pending_smart_contract_blocks(db)
    deployed_contract_address = list_of_smart_contracts[0]

    return deployed_contract_address, contract_interface