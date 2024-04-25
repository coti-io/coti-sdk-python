from dotenv import load_dotenv

from confidential_erc20_methods import *

# script deploys (or uses already deployed) confidential erc20 contract
# that is possible to transfer funds in a clear or encrypted manner
# pending enhancements: approval, allowance, mint in encrypted manner and gas estimations
def main():
    account_hex_encryption_key, eoa, eoa_private_key, web3 = init()

    gas_limit = 10000000
    gas_price_gwei = 30
    token_name = "My Confidential Token"
    token_symbol = "CTOK"
    token_initial_balance = 500000000

    tx_params = {'web3': web3, 'gas_limit': gas_limit, 'gas_price_gwei': gas_price_gwei,
                 'eoa_private_key': eoa_private_key}
    deployed_contract = deploy(account_hex_encryption_key, eoa, token_initial_balance,
                               token_name, token_symbol, tx_params)
    view_functions(deployed_contract, eoa)
    testing_functions(deployed_contract, eoa, account_hex_encryption_key, tx_params)


def deploy(account_hex_encryption_key, eoa, initial_balance, name, symbol, tx_params):
    kwargs = {
        'name_': name,
        'symbol_': symbol,
        'initialSupply': initial_balance
    }
    contract_name = "ERC20Example"
    contract_file_name = "ERC20Example.sol"
    contract_directory = "examples/"
    relative_to_mpc_core = "../lib/MpcCore.sol"
    deployed_contract, was_already_deployed = \
        get_deployed_contract(contract_name, contract_file_name, contract_directory, tx_params, kwargs,
                              relative_to_mpc_core)
    print('contract address: ', deployed_contract.address)
    if not was_already_deployed:
        account_balance = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
        assert account_balance == initial_balance
    return deployed_contract


def init():
    load_dotenv()  # loading .env
    eoa_private_key = get_account_private_key()  # Get EOA Private key for execution
    account_hex_encryption_key = get_hex_account_encryption_key()  # Get Hex key used to encrypt on network
    eoa = get_eoa(eoa_private_key)  # Get EOA
    web3 = init_web3(get_node_https_address(), eoa)  # Init connection to node
    validate_minimum_balance(web3)  # validate minimum balance
    return account_hex_encryption_key, eoa, eoa_private_key, web3


def testing_functions(deployed_contract, eoa, account_hex_encryption_key, tx_params):
    # Generate a new Ethereum account for Alice
    alice_address = Account.create()
    plaintext_integer = 5

    account_balance_at_first = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
    account_balance_before = test_transfer(account_balance_at_first, account_hex_encryption_key, alice_address,
                                           deployed_contract, eoa, plaintext_integer, tx_params)

    account_balance_before = test_transfer_clear(account_balance_before, account_hex_encryption_key, alice_address,
                                                 deployed_contract, eoa, plaintext_integer, tx_params)

    account_balance_at_end = test_transfer_input_text(account_balance_before, account_hex_encryption_key, alice_address,
                                                      deployed_contract, eoa, plaintext_integer, tx_params)

    # bob_address = Account.from_key('0x48bd95ee72b683c16cb0852dd5659f9cbed331955685743ea960a2e3d0cd1317')
    # bob_hex_encryption_key = bytes.fromhex('ff15d2a0902744ba1c4bc8550402261e')

    # account_balance_before = test_transfer_clear_no_allowance(account_balance_before, account_hex_encryption_key,
    #                                                           alice_address, deployed_contract, eoa, plaintext_integer,
    #                                                           tx_params, bob_address)

    # test_approve_clear(account_hex_encryption_key, deployed_contract, eoa, plaintext_integer, tx_params, bob_address)

    # account_balance_before = test_transfer_from(account_balance_before, account_hex_encryption_key, alice_address,
    #                                             deployed_contract, eoa, plaintext_integer, tx_params, bob_address,
    #                                             bob_hex_encryption_key)
    #
    # account_balance_at_end = test_transfer_from_clear(account_balance_before, account_hex_encryption_key, alice_address,
    #                                                   deployed_contract, eoa, plaintext_integer, tx_params)
    #
    # test_approve(account_hex_encryption_key, deployed_contract, eoa, tx_params)

    print('account balance at first: ', account_balance_at_first, ' account balance at end:', account_balance_at_end)


def test_approve(account_hex_encryption_key, deployed_contract, eoa, tx_params):
    print("************* Approve InputText 50 to my address *************")
    kwargs = {'_spender': eoa.address, '_itCT': 50, '_itSignature': bytes(65)}
    tx_receipt = approve(deployed_contract, kwargs, 50, account_hex_encryption_key, eoa, tx_params)
    print(tx_receipt)
    allowance_cipher_text = deployed_contract.functions.allowance(eoa.address, eoa.address).call({'from': eoa.address})
    allowance = decrypt_value(allowance_cipher_text, account_hex_encryption_key)
    assert allowance >= 50


def test_transfer_from_clear(account_balance_before, account_hex_encryption_key, alice_address, deployed_contract, eoa,
                             plaintext_integer, tx_params):
    print("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    kwargs = {'_from': eoa.address, '_to': alice_address.address, '_value': plaintext_integer}
    tx_receipt = transfer_from_clear(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    account_balance_after = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
    assert account_balance_before - plaintext_integer == account_balance_after
    return account_balance_after


def test_transfer_from(account_balance_before, account_hex_encryption_key, alice_address, deployed_contract, eoa,
                       plaintext_integer, tx_params, bob_address, bob_hex_encryption_key):
    print("************* Transfer clear ", plaintext_integer, " from my account to Alice with allowance **********")
    kwargs = {'_from': eoa.address, '_to': bob_address.address, '_itCT': 5,
              '_itSignature': bytes(65), 'revealRes': False}
    tx_receipt = transfer_from(deployed_contract, kwargs, bob_address, bob_hex_encryption_key, 5,
                               tx_params)
    print(tx_receipt)
    account_balance_after = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
    assert account_balance_before - plaintext_integer == account_balance_after
    return account_balance_after


def test_approve_clear(account_hex_encryption_key, deployed_contract, eoa, plaintext_integer, tx_params, bob_address):
    print("************* Approve ", plaintext_integer * 10, " to my address *************")
    allowance_amount = plaintext_integer * 10
    kwargs = {'_spender': bob_address.address, '_value': allowance_amount}
    tx_receipt = approveClear(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    allowance_cipher_text = deployed_contract.functions.allowance(eoa.address, bob_address.address).call(
        {'from': eoa.address})
    allowance = decrypt_value(allowance_cipher_text, account_hex_encryption_key)
    assert allowance == allowance_amount


def test_transfer_clear_no_allowance(account_balance_before, account_hex_encryption_key, alice_address,
                                     deployed_contract, eoa, plaintext_integer, tx_params, bob_address):
    print("************* Transfer clear ", plaintext_integer, " from my account to Alice without allowance **********")
    allowance_cipher_text = deployed_contract.functions.allowance(eoa.address, bob_address.address).call(
        {'from': eoa.address})
    allowance = decrypt_value(allowance_cipher_text, account_hex_encryption_key) if allowance_cipher_text else None
    amount = allowance if allowance and allowance > 0 else plaintext_integer
    validation_amount = allowance if allowance and allowance > 0 else 0
    kwargs = {'_from': bob_address.address, '_to': alice_address.address, '_itCT': amount, '_itSignature': bytes(65),
              'revealRes': False}
    tx_receipt = transfer_from(deployed_contract, kwargs, eoa, account_hex_encryption_key, amount, tx_params)
    print(tx_receipt)
    account_balance_after = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
    assert account_balance_before - validation_amount == account_balance_after
    account_balance_before = account_balance_before - validation_amount if allowance and allowance > 0 else account_balance_before
    return account_balance_before


def test_transfer_input_text(account_balance_before, account_hex_encryption_key, alice_address, deployed_contract, eoa,
                             plaintext_integer, tx_params):
    print("************* Transfer IT ", plaintext_integer, " to Alice *************")
    kwargs = {'_to': alice_address.address, '_itCT': 5, '_itSignature': bytes(65), 'revealRes': False}
    tx_receipt = transfer_encrypted(deployed_contract, kwargs, eoa, account_hex_encryption_key, tx_params)
    print(tx_receipt)
    account_balance_after = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
    assert account_balance_before - plaintext_integer == account_balance_after
    return account_balance_after


def test_transfer_clear(account_balance_before, account_hex_encryption_key, alice_address, deployed_contract, eoa,
                        plaintext_integer, tx_params):
    print("************* Transfer again, clear ", plaintext_integer, " to Alice *************")
    kwargs = {'_to': alice_address.address, '_value': plaintext_integer}
    tx_receipt = transfer_clear(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    account_balance_after = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
    assert account_balance_before - plaintext_integer == account_balance_after
    return account_balance_after


def test_transfer(account_balance_before, account_hex_encryption_key, alice_address, deployed_contract, eoa,
                  plaintext_integer, tx_params):
    print("************* Transfer clear ", plaintext_integer, " to Alice *************")
    kwargs = {'_to': alice_address.address, '_value': plaintext_integer, 'revealRes': True}
    tx_receipt = transfer(deployed_contract, kwargs, tx_params)
    print(tx_receipt)
    account_balance_after = get_account_balance(account_hex_encryption_key, deployed_contract, eoa)
    assert account_balance_before - plaintext_integer == account_balance_after
    return account_balance_after


def view_functions(deployed_contract, eoa):
    print("************* View functions *************")
    name = deployed_contract.functions.name().call({'from': eoa.address})
    print("Function call result name:", name)
    symbol = deployed_contract.functions.symbol().call({'from': eoa.address})
    print("Function call result symbol:", symbol)
    decimals = deployed_contract.functions.decimals().call({'from': eoa.address})
    print("Function call result decimals:", decimals)
    total_supply = deployed_contract.functions.totalSupply().call({'from': eoa.address})
    print("Function call result totalSupply:", total_supply)


if __name__ == "__main__":
    main()
