import os

from eth_account import Account
from web3 import Web3
from web3.middleware import geth_poa_middleware

from crypto_utils import block_size, decrypt

SOLC_VERSION = '0.8.19'


def web3_connected(web3):
    return web3.is_connected()


def print_network_details(web3):
    print('provider: ', web3.eth.w3.provider.endpoint_uri)
    print('chain-id: ', web3.eth.chain_id)
    print('latest block: ', web3.eth.get_block('latest').get('hash').hex())


def print_account_details(web3):
    print('account address:', web3.eth.default_account.address)
    print('account balance: ', get_native_balance(web3), 'wei (', web3.from_wei(get_native_balance(web3), 'ether'),
          ' ether)')
    print('account nonce: ', get_nonce(web3))


def init_web3(node_https_address, eoa, error_not_connected=True):
    web3 = Web3(Web3.HTTPProvider(node_https_address))
    web3.eth.default_account = eoa
    web3.middleware_onion.inject(geth_poa_middleware, layer=0)
    if error_not_connected:
        if not web3_connected(web3):
            raise Exception("Connection to node failed!")
    print_network_details(web3)
    print_account_details(web3)
    return web3


def get_eoa(account_private_key):
    eoa = Account.from_key(account_private_key)
    if address_valid(eoa.address):
        return eoa
    raise Exception("eoa from private key is not valid!")


def validate_address(address):
    return {'valid': Web3.is_address(address), 'safe': Web3.to_checksum_address(address)}


def get_latest_block(web3):
    return web3.eth.get_block('latest')


def get_nonce(web3):
    return web3.eth.get_transaction_count(web3.eth.default_account.address)


def get_address_valid_and_checksum(address):
    return {'valid': Web3.is_address(address), 'safe': Web3.to_checksum_address(address)}


def address_valid(address):
    return get_address_valid_and_checksum(address)['valid']


def get_native_balance(web3, address=None):
    if address is None:
        return web3.eth.get_balance(web3.eth.default_account.address)
    if address is not None and address_valid(address):
        return web3.eth.get_balance(address)
    if not address_valid(address):
        raise Exception('address ', address, ' is not valid!')


def load_contract(file_path):
    # Ensure the file path is valid
    if not os.path.exists(file_path):
        raise Exception(f"The file {file_path} does not exists")

    # Read the Solidity source code from the file
    with open(file_path, 'r') as file:
        return file.read()


def transfer_native(web3, recipient_address, private_key, amount_to_transfer_ether, native_gas_units):
    tx = {
        'to': recipient_address,
        'from': web3.eth.default_account.address,
        'value': web3.to_wei(amount_to_transfer_ether, 'ether'),  # Transaction value (0.1 Ether in this example)
        'nonce': get_nonce(web3),
        'gas': native_gas_units,  # Gas limit for the transaction
        'gasPrice': web3.eth.gas_price,
        'chainId': web3.eth.chain_id
    }
    validate_gas_estimation(web3, tx)
    tx_receipt = sign_and_send_tx(web3, private_key, tx)
    return tx_receipt


def validate_gas_estimation(web3, tx):
    valid, gas_estimate = is_gas_units_estimation_valid(web3, tx)
    if valid is False:
        raise Exception('not enough gas for tx (provided: ' + str(tx.get('gas')) + ' needed by estimation: ' + str(
            gas_estimate) + ')')


def is_gas_units_estimation_valid(web3, tx):
    estimate_gas = web3.eth.estimate_gas(tx)
    if tx['gas'] >= estimate_gas:
        return True, estimate_gas
    return False, estimate_gas


def get_function_signature(function_abi):
    # Extract the input types from the ABI
    input_types = ','.join([param['type'] for param in function_abi.get('inputs', [])])

    # Generate the function signature
    return f"{function_abi['name']}({input_types})"


def deploy_contract(contract, kwargs, tx_params):
    func = contract.constructor(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def exec_func_via_transaction(func, tx_params):
    web3 = tx_params['web3']
    gas_limit = tx_params['gas_limit']
    gas_price_gwei = tx_params['gas_price_gwei']
    account_private_key = tx_params['eoa_private_key']
    tx = func.build_transaction({
        'from': web3.eth.default_account.address,
        'chainId': web3.eth.chain_id,
        'nonce': get_nonce(web3),
        'gas': gas_limit,
        'gasPrice': web3.to_wei(gas_price_gwei, 'gwei')
    })
    # validate_gas_estimation(web3, tx)
    tx_receipt = sign_and_send_tx(web3, account_private_key, tx)
    return tx_receipt


def sign_and_send_tx(web3, private_key, transaction):
    try:
        signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
    except Exception as e:
        raise Exception(f"Failed to sign the transaction: {e}")
    try:
        tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    except Exception as e:
        raise Exception(f"Failed to send the transaction: {e}")
    try:
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    except Exception as e:
        raise Exception(f"Failed to wait for the transaction receipt: {e}")
    return tx_receipt


def decrypt_value(contract_value, user_key):
    # Convert ct to bytes (big-endian)
    byte_array = contract_value.to_bytes(32, byteorder='big')

    # Split ct into two 128-bit arrays r and cipher
    cipher = byte_array[:block_size]
    r = byte_array[block_size:]

    # Decrypt the cipher
    decrypted_message = decrypt(user_key, r, cipher)

    # Print the decrypted cipher
    decrypted_balance = int.from_bytes(decrypted_message, 'big')

    return decrypted_balance
