from dotenv import load_dotenv

from examples.basics.utils import *

# script demonstrates basic network capabilities on encrypt/decrypt of values saved in a contract
def main():
    account_hex_encryption_key, eoa, eoa_private_key, web3 = init()

    gas_limit = 10000000
    gas_price_gwei = 30

    tx_params = {'web3': web3, 'gas_limit': gas_limit, 'gas_price_gwei': gas_price_gwei,
                 'eoa_private_key': eoa_private_key}
    deployed_contract = deploy(account_hex_encryption_key, eoa, tx_params)

    test_get_clear_value(deployed_contract, eoa)
    test_encrypt_decrypt_success(account_hex_encryption_key, deployed_contract, eoa, tx_params)

    some_other_aes_key = generate_aes_key()
    test_user_encrypt_decrypt_fail(some_other_aes_key, deployed_contract, eoa, tx_params)

    test_network_encrypt_decrypt_fail(account_hex_encryption_key, deployed_contract, eoa, tx_params)


def test_encrypt_decrypt_success(account_hex_encryption_key, deployed_contract, eoa, tx_params):
    user_some_value_clear, encrypted_value = set_encrypt_fetch_decrypt(deployed_contract, tx_params)
    user_some_value_encrypted = get_user_value(deployed_contract, eoa)
    encrypted_value_int_value = int(encrypted_value.hex(), 16)
    assert encrypted_value_int_value == user_some_value_encrypted
    user_some_value_decrypted = decrypt_value(user_some_value_encrypted, account_hex_encryption_key)
    assert user_some_value_decrypted == user_some_value_clear


def test_user_encrypt_decrypt_fail(account_hex_encryption_key, deployed_contract, eoa, tx_params):
    user_some_value_clear = set_encrypt_fetch_decrypt(deployed_contract, tx_params)
    user_some_value_encrypted = get_user_value(deployed_contract, eoa)
    user_some_value_decrypted = decrypt_value(user_some_value_encrypted, account_hex_encryption_key)
    assert user_some_value_decrypted != user_some_value_clear


def test_network_encrypt_decrypt_fail(account_hex_encryption_key, deployed_contract, eoa, tx_params):
    user_some_value_clear = set_encrypt_fetch_decrypt(deployed_contract, tx_params)
    network_some_value_encrypted = get_network_value(deployed_contract, eoa)
    network_some_value_decrypted = decrypt_value(network_some_value_encrypted, account_hex_encryption_key)
    assert network_some_value_decrypted != user_some_value_clear


def set_encrypt_fetch_decrypt(deployed_contract, tx_params):
    user_some_value_clear = 6
    kwargs = {'_value': user_some_value_clear}
    tx_receipt = setSomeEncryptedValueOf(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    kwargs = {}
    tx_receipt = setUserSomeEncryptedValueOf(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    return user_some_value_clear, tx_receipt.logs[0].data


def get_user_value(deployed_contract, eoa):
    return deployed_contract.functions.getUserSomeEncryptedValueOf().call({'from': eoa.address})


def get_network_value(deployed_contract, eoa):
    return deployed_contract.functions.getNetworkSomeEncryptedValueOf().call({'from': eoa.address})


def test_get_clear_value(deployed_contract, eoa):
    some_value = deployed_contract.functions.someValueOf().call({'from': eoa.address})
    assert some_value == 5


def setUserSomeEncryptedValueOf(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.setUserSomeEncryptedValueOf(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def setSomeEncryptedValueOf(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.setSomeEncryptedValueOf(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def someEncryptedValueOf(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.someEncryptedValueOf(**kwargs)
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
