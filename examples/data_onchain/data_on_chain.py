from examples.onboard.onboard_account import *


# script demonstrates basic network capabilities on encrypt/decrypt of values saved in a contract
def main():
    account_hex_encryption_key, eoa, eoa_private_key, web3 = init()

    gas_limit = 10000000
    gas_price_gwei = 30

    tx_params = {'web3': web3, 'gas_limit': gas_limit, 'gas_price_gwei': gas_price_gwei,
                 'eoa_private_key': eoa_private_key}
    deployed_contract = deploy(account_hex_encryption_key, eoa, tx_params)

    basic_get_value(deployed_contract, eoa)
    a = basic_clear_encrypt_decrypt(account_hex_encryption_key, deployed_contract, eoa, tx_params)

    some_other_aes_key = generate_aes_key()
    basic_decryption_failure(some_other_aes_key, deployed_contract, eoa, tx_params)

    network_decryption_failure(account_hex_encryption_key, deployed_contract, eoa, tx_params)

    b = basic_encrypted_encrypt_decrypt(account_hex_encryption_key, deployed_contract, eoa,
                                        account_hex_encryption_key, tx_params)

    basic_add_computation(deployed_contract, tx_params, eoa, account_hex_encryption_key, a + b)
    compute_add_with_different_account(eoa_private_key, gas_limit, gas_price_gwei, web3, deployed_contract, a + b)


# create another EOA and do the same computation method demonstrating the capability to use the same contract method
# just with different account and having the correct result back encrypted and decrypted with the other EOA
def compute_add_with_different_account(eoa_private_key, gas_limit, gas_price_gwei, web3, deployed_contract, result):
    alice_decrypted_aes_key, alice_eoa, alice_tx_params = create_another_account(eoa_private_key, gas_limit,
                                                                                 gas_price_gwei, web3)
    basic_add_computation(deployed_contract, alice_tx_params, alice_eoa, alice_decrypted_aes_key, result)


# create another EOA account, fund it and onboard it so that you could have the aes key of it
def create_another_account(eoa_private_key, gas_limit, gas_price_gwei, web3):
    alice_eoa = Account.create()
    tx_receipt = transfer_native(web3, alice_eoa.address, eoa_private_key, 0.5, gas_limit)
    print(tx_receipt)
    alice_private_key = alice_eoa._private_key.hex()[2:]
    alice_web3 = init_web3(get_node_https_address(), alice_eoa)
    onboard_deployed_contract = get_contract(alice_web3, devnet_onboard_contract['abi'],
                                             devnet_onboard_contract['bytecode'],
                                             devnet_onboard_contract['address'])
    alice_tx_params = {'web3': alice_web3, 'gas_limit': gas_limit, 'gas_price_gwei': gas_price_gwei,
                       'eoa_private_key': alice_private_key}
    alice_decrypted_aes_key = onboard_for_aes_key(onboard_deployed_contract, alice_private_key, alice_tx_params)
    return alice_decrypted_aes_key, alice_eoa, alice_tx_params


def basic_add_computation(deployed_contract, tx_params, eoa, account_hex_encryption_key, sum_result):
    kwargs = {}
    tx_receipt = add_one_encrypted_value_with_another_on_chain(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    user_encrypted_arithmetic_result = get_user_arithmetic_result(deployed_contract, eoa)
    user_decrypted_arithmetic_result = decrypt_value(user_encrypted_arithmetic_result, account_hex_encryption_key)
    assert sum_result == user_decrypted_arithmetic_result


# Sending tx with encrypted value, that value will be saved in the field of the contract
# flow: sending tx, asserting value was sent encrypted by data recorded in the block
# receiving back encrypted value via func and event log, asserting that they are the same
# decrypting value and asserting it is as the clear value
def basic_encrypted_encrypt_decrypt(account_hex_encryption_key, deployed_contract, eoa,
                                    hex_account_private_key, tx_params):
    tx_receipt, user_some_value_clear, input_text = \
        save_input_text_network_encrypted_in_contract(deployed_contract, account_hex_encryption_key, eoa,
                                                      hex_account_private_key, tx_params)
    print(tx_receipt)
    validate_block_has_tx_input_encrypted_value(tx_params, tx_receipt, user_some_value_clear,
                                                account_hex_encryption_key, input_text)
    kwargs = {}
    tx_receipt = save_network_encrypted_to_user_encrypted_input_in_contract(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    user_cipher_text_from_block = tx_receipt.logs[0].data
    user_cipher_text_from_block_int_value = int(user_cipher_text_from_block.hex(), 16)
    user_cipher_text_from_contract = get_user_value_encrypted_input(deployed_contract, eoa)
    # assert that same value back from view func is one back from event
    assert user_cipher_text_from_block_int_value == user_cipher_text_from_contract
    user_cipher_text_decrypted = decrypt_value(user_cipher_text_from_contract, account_hex_encryption_key)
    # assert that value saved encrypted within the network is one sent
    assert user_cipher_text_decrypted == user_some_value_clear
    return user_cipher_text_decrypted


# Sending tx with clear value as tx input, that value will be saved encrypted in the contract (by network key)
# flow: sending tx, asserting value was sent clear by data recorded in the block
# receiving back encrypted value via func and event log, asserting that they are the same
# decrypting value and asserting it is as the clear value
def basic_clear_encrypt_decrypt(account_hex_encryption_key, deployed_contract, eoa, tx_params):
    user_some_value_clear, tx_receipt = save_clear_value_network_encrypted_in_contract(deployed_contract, tx_params)
    validate_block_has_tx_input_clear_value(tx_params, tx_receipt, user_some_value_clear)
    tx_receipt = save_network_encrypted_to_user_encrypted_in_contract(deployed_contract, tx_params, tx_receipt)
    user_encrypted_value_from_block = tx_receipt.logs[0].data
    user_encrypted_value_from_block_int_value = int(user_encrypted_value_from_block.hex(), 16)
    user_encrypted_value_from_contract = get_user_encrypted_from_contract(deployed_contract, eoa)
    # assert that same value back from view func is one back from event
    assert user_encrypted_value_from_block_int_value == user_encrypted_value_from_contract
    user_some_value_decrypted = decrypt_value(user_encrypted_value_from_contract, account_hex_encryption_key)
    # assert that value saved encrypted within the network is one sent
    assert user_some_value_decrypted == user_some_value_clear
    return user_some_value_decrypted


def save_network_encrypted_to_user_encrypted_in_contract(deployed_contract, tx_params, tx_receipt):
    kwargs = {}
    tx_receipt = setUserSomeEncryptedValue(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    return tx_receipt


# asserting that if trying to decrypt value back that was encrypted by user key can't be
# deciphered by another key
def basic_decryption_failure(some_other_account_hex_encryption_key, deployed_contract, eoa, tx_params):
    user_some_value_clear, _ = save_clear_value_network_encrypted_in_contract(deployed_contract, tx_params)
    user_some_value_encrypted = get_user_encrypted_from_contract(deployed_contract, eoa)
    user_some_value_decrypted = decrypt_value(user_some_value_encrypted, some_other_account_hex_encryption_key)
    # assert that value back cant be decrypted by some other key
    assert user_some_value_decrypted != user_some_value_clear


# asserting that if trying to decrypt the value saved with network key with user key, it will fail
def network_decryption_failure(account_hex_encryption_key, deployed_contract, eoa, tx_params):
    user_some_value_clear, _ = save_clear_value_network_encrypted_in_contract(deployed_contract, tx_params)
    network_some_value_encrypted = get_network_value(deployed_contract, eoa)
    network_some_value_decrypted = decrypt_value(network_some_value_encrypted, account_hex_encryption_key)
    # assert that network encrypted value cant be decrypted by user key
    assert network_some_value_decrypted != user_some_value_clear


def save_input_text_network_encrypted_in_contract(deployed_contract, account_hex_encryption_key, eoa,
                                                  hex_account_private_key, tx_params):
    clear_input = 8
    kwargs = {'_itCT': clear_input, '_itSignature': bytes(65)}
    func = deployed_contract.functions.setSomeEncryptedValueEncryptedInput(**kwargs)
    func_sig = get_function_signature(func.abi)
    eoa_private_key = tx_params['eoa_private_key']
    hex_account_private_key = bytes.fromhex(eoa_private_key)
    input_text, signature = build_input_text(clear_input, account_hex_encryption_key, eoa, deployed_contract, func_sig,
                                             hex_account_private_key)
    kwargs['_itCT'] = input_text
    kwargs['_itSignature'] = signature
    func = deployed_contract.functions.setSomeEncryptedValueEncryptedInput(**kwargs)
    return exec_func_via_transaction(func, tx_params), clear_input, input_text


def save_clear_value_network_encrypted_in_contract(deployed_contract, tx_params):
    user_some_value_clear = 7
    kwargs = {'_value': user_some_value_clear}
    tx_receipt = setSomeEncryptedValue(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    return user_some_value_clear, tx_receipt


def validate_block_has_tx_input_clear_value(tx_params, tx_receipt, user_some_value_clear):
    tx_from_block = tx_params['web3'].eth.get_transaction_by_block(tx_receipt['blockHash'],
                                                                   tx_receipt['transactionIndex'])
    print(tx_from_block)
    user_some_value_clear_from_tx = tx_from_block['input'].hex()[10:]
    assert int(user_some_value_clear_from_tx) == user_some_value_clear


def validate_block_has_tx_input_encrypted_value(tx_params, tx_receipt, user_some_value_clear,
                                                account_hex_encryption_key, input_text):
    tx_from_block = tx_params['web3'].eth.get_transaction_by_block(tx_receipt['blockHash'],
                                                                   tx_receipt['transactionIndex'])
    print(tx_from_block)
    input_text_from_tx = tx_from_block['input'].hex()[10:74]
    # assert that value encrypted locally was saved in block
    assert input_text == int(input_text_from_tx, 16)
    # assert that value saved in block is not clear
    assert str(input_text_from_tx) != str(user_some_value_clear)
    decrypted_input_from_tx = decrypt_value(int(input_text_from_tx, 16), account_hex_encryption_key)
    # assert that value saved in block is as clear after decryption
    assert int(decrypted_input_from_tx) == user_some_value_clear


def get_user_encrypted_from_contract(deployed_contract, eoa):
    return deployed_contract.functions.getUserSomeEncryptedValue().call({'from': eoa.address})


def get_user_value_encrypted_input(deployed_contract, eoa):
    return deployed_contract.functions.getUserSomeEncryptedValueEncryptedInput().call({'from': eoa.address})


def get_network_value(deployed_contract, eoa):
    return deployed_contract.functions.getNetworkSomeEncryptedValue().call({'from': eoa.address})


def get_user_arithmetic_result(deployed_contract, eoa):
    return deployed_contract.functions.getUserArithmeticResult().call({'from': eoa.address})


# normal solidity view function to get a value that was saved,
# in this case saved when the contract constructor was executed
def basic_get_value(deployed_contract, eoa):
    some_value = deployed_contract.functions.getSomeValue().call({'from': eoa.address})
    assert some_value == 5


def setUserSomeEncryptedValue(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.setUserSomeEncryptedValue(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def save_network_encrypted_to_user_encrypted_input_in_contract(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.setUserSomeEncryptedValueEncryptedInput(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def setSomeEncryptedValue(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.setSomeEncryptedValue(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def someEncryptedValueOf(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.someEncryptedValueOf(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def add_one_encrypted_value_with_another_on_chain(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.add(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def init():
    load_dotenv()  # loading .env
    eoa_private_key = get_account_private_key()  # Get EOA Private key for execution
    account_hex_encryption_key = get_hex_account_encryption_key()  # Get Hex key used to encrypt on network
    eoa = get_eoa(eoa_private_key)  # Get EOA
    web3 = init_web3(get_node_https_address(), eoa)  # Init connection to node
    validate_minimum_balance(web3)  # validate minimum balance
    return account_hex_encryption_key, eoa, eoa_private_key, web3


def deploy(account_hex_encryption_key, eoa, tx_params):
    kwargs = {}
    contract_name = "DataOnChain"
    contract_file_name = contract_name + ".sol"
    relative_to_contracts_directory = "examples/"
    relative_to_mpc_core = "../lib/MpcCore.sol"
    deployed_contract, was_already_deployed = \
        get_deployed_contract(contract_name, contract_file_name, relative_to_contracts_directory, tx_params, kwargs,
                              relative_to_mpc_core)
    print('contract address: ', deployed_contract.address)

    return deployed_contract


if __name__ == "__main__":
    main()
