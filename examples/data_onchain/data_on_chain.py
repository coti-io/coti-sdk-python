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
    make_sure_data_is_safe(eoa, web3, deployed_contract, tx_params)


def make_sure_data_is_safe(eoa, web3, deployed_contract, tx_params):
    some_other_contract_keeping_data = {"contract_name": "DataOnChain",
                                        "address": "0xA4e3271337f9d1f4C3dc1991D8137d0ccE05b60b",
                                        "abi": [{"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
                                                {"anonymous": false, "inputs": [
                                                    {"indexed": true, "internalType": "address", "name": "_from",
                                                     "type": "address"},
                                                    {"indexed": false, "internalType": "ctUint64",
                                                     "name": "ctUserSomeEncryptedValue", "type": "uint256"}],
                                                 "name": "UserEncryptedValue",
                                                 "type": "event"},
                                                {"inputs": [], "name": "add", "outputs": [],
                                                 "stateMutability": "nonpayable", "type": "function"},
                                                {"inputs": [], "name": "getNetworkSomeEncryptedValue",
                                                 "outputs": [
                                                     {"internalType": "ctUint64", "name": "ctSomeEncryptedValue",
                                                      "type": "uint256"}],
                                                 "stateMutability": "view", "type": "function"},
                                                {"inputs": [], "name": "getNetworkSomeEncryptedValueEncryptedInput",
                                                 "outputs": [
                                                     {"internalType": "ctUint64", "name": "ctSomeEncryptedValue",
                                                      "type": "uint256"}],
                                                 "stateMutability": "view", "type": "function"},
                                                {"inputs": [], "name": "getSomeValue", "outputs": [
                                                    {"internalType": "uint64", "name": "value", "type": "uint64"}],
                                                 "stateMutability": "nonpayable",
                                                 "type": "function"},
                                                {"inputs": [], "name": "getUserArithmeticResult",
                                                 "outputs": [
                                                     {"internalType": "ctUint64", "name": "value", "type": "uint256"}],
                                                 "stateMutability": "nonpayable", "type": "function"},
                                                {"inputs": [], "name": "getUserSomeEncryptedValue",
                                                 "outputs": [{"internalType": "ctUint64",
                                                              "name": "ctSomeEncryptedValue",
                                                              "type": "uint256"}],
                                                 "stateMutability": "view", "type": "function"},
                                                {"inputs": [], "name": "getUserSomeEncryptedValueEncryptedInput",
                                                 "outputs": [
                                                     {"internalType": "ctUint64", "name": "ctSomeEncryptedValue",
                                                      "type": "uint256"}],
                                                 "stateMutability": "view", "type": "function"},
                                                {"inputs": [
                                                    {"internalType": "uint64", "name": "_value", "type": "uint64"}],
                                                    "name": "setSomeEncryptedValue", "outputs": [],
                                                    "stateMutability": "nonpayable", "type": "function"}, {
                                                    "inputs": [{"internalType": "ctUint64", "name": "_itCT",
                                                                "type": "uint256"},
                                                               {"internalType": "bytes", "name": "_itSignature",
                                                                "type": "bytes"}],
                                                    "name": "setSomeEncryptedValueEncryptedInput", "outputs": [],
                                                    "stateMutability": "nonpayable",
                                                    "type": "function"},
                                                {"inputs": [], "name": "setUserSomeEncryptedValue", "outputs": [],
                                                 "stateMutability": "nonpayable",
                                                 "type": "function"},
                                                {"inputs": [], "name": "setUserSomeEncryptedValueEncryptedInput",
                                                 "outputs": [],
                                                 "stateMutability": "nonpayable", "type": "function"}],
                                        "bytecode": "0x608060405234801561001057600080fd5b5060056000806101000a81548167ffffffffffffffff021916908367ffffffffffffffff160217905550610d1f806100496000396000f3fe608060405234801561001057600080fd5b50600436106100a95760003560e01c806371091de31161007157806371091de31461011a5780638d7eadec14610138578063a2e1286914610156578063a40674b714610174578063af384ac714610192578063fee511d6146101ae576100a9565b806305bdf1db146100ae57806318312545146100cc5780634f0bc491146100ea5780634f2be91f1461010657806361eeffcd14610110575b600080fd5b6100b66101b8565b6040516100c3919061086c565b60405180910390f35b6100d46101c2565b6040516100e1919061086c565b60405180910390f35b61010460048036038101906100ff9190610922565b6101cc565b005b61010e61024e565b005b61011861028f565b005b610122610301565b60405161012f919061086c565b60405180910390f35b61014061030b565b60405161014d919061086c565b60405180910390f35b61015e610315565b60405161016b919061086c565b60405180910390f35b61017c61031f565b60405161018991906109a5565b60405180910390f35b6101ac60048036038101906101a791906109ec565b61033c565b005b6101b661035c565b005b6000600354905090565b6000600154905090565b6101d461080d565b8381600001818152505082828080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505081602001819052506000610236826103ce565b905061024181610475565b6004819055505050505050565b600061025b600354610512565b9050600061026a600454610512565b9050600061027883836105af565b90506102848133610646565b600581905550505050565b600061029c600454610512565b90506102a88133610646565b6002819055503373ffffffffffffffffffffffffffffffffffffffff167f958094500e56c659b01cdefb25c66c88f025c3c800f69b2a2141f8c73b30e0566002546040516102f6919061086c565b60405180910390a250565b6000600454905090565b6000600554905090565b6000600254905090565b60008060009054906101000a900467ffffffffffffffff16905090565b600061034782610705565b905061035281610475565b6003819055505050565b6000610369600354610512565b90506103758133610646565b6001819055503373ffffffffffffffffffffffffffffffffffffffff167f958094500e56c659b01cdefb25c66c88f025c3c800f69b2a2141f8c73b30e0566001546040516103c3919061086c565b60405180910390a250565b6000606473ffffffffffffffffffffffffffffffffffffffff1663e4f36e10600480811115610400576103ff610a19565b5b60f81b846000015185602001516040518463ffffffff1660e01b815260040161042b93929190610b22565b6020604051808303816000875af115801561044a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061046e9190610b8c565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663c50c9c026004808111156104a7576104a6610a19565b5b60f81b846040518363ffffffff1660e01b81526004016104c8929190610bb9565b6020604051808303816000875af11580156104e7573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061050b9190610b8c565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d2c135e560048081111561054457610543610a19565b5b60f81b846040518363ffffffff1660e01b8152600401610565929190610bb9565b6020604051808303816000875af1158015610584573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906105a89190610b8c565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16638c5d01506105db60048060006107ac565b85856040518463ffffffff1660e01b81526004016105fb93929190610c1d565b6020604051808303816000875af115801561061a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061063e9190610b8c565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e6860048081111561067857610677610a19565b5b60f81b858560405160200161068d9190610cce565b6040516020818303038152906040526040518463ffffffff1660e01b81526004016106ba93929190610b22565b6020604051808303816000875af11580156106d9573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906106fd9190610b8c565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b6060048081111561073757610736610a19565b5b60f81b8467ffffffffffffffff166040518363ffffffff1660e01b8152600401610762929190610bb9565b6020604051808303816000875af1158015610781573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906107a59190610b8c565b9050919050565b60008160028111156107c1576107c0610a19565b5b60ff1660088460048111156107d9576107d8610a19565b5b61ffff16901b61ffff1660108660048111156107f8576107f7610a19565b5b62ffffff16901b171760e81b90509392505050565b604051806040016040528060008152602001606081525090565b6000819050919050565b6000819050919050565b600061085661085161084c84610827565b610831565b610827565b9050919050565b6108668161083b565b82525050565b6000602082019050610881600083018461085d565b92915050565b600080fd5b600080fd5b61089a81610827565b81146108a557600080fd5b50565b6000813590506108b781610891565b92915050565b600080fd5b600080fd5b600080fd5b60008083601f8401126108e2576108e16108bd565b5b8235905067ffffffffffffffff8111156108ff576108fe6108c2565b5b60208301915083600182028301111561091b5761091a6108c7565b5b9250929050565b60008060006040848603121561093b5761093a610887565b5b6000610949868287016108a8565b935050602084013567ffffffffffffffff81111561096a5761096961088c565b5b610976868287016108cc565b92509250509250925092565b600067ffffffffffffffff82169050919050565b61099f81610982565b82525050565b60006020820190506109ba6000830184610996565b92915050565b6109c981610982565b81146109d457600080fd5b50565b6000813590506109e6816109c0565b92915050565b600060208284031215610a0257610a01610887565b5b6000610a10848285016109d7565b91505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60007fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b610a7d81610a48565b82525050565b610a8c81610827565b82525050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610acc578082015181840152602081019050610ab1565b60008484015250505050565b6000601f19601f8301169050919050565b6000610af482610a92565b610afe8185610a9d565b9350610b0e818560208601610aae565b610b1781610ad8565b840191505092915050565b6000606082019050610b376000830186610a74565b610b446020830185610a83565b8181036040830152610b568184610ae9565b9050949350505050565b610b6981610827565b8114610b7457600080fd5b50565b600081519050610b8681610b60565b92915050565b600060208284031215610ba257610ba1610887565b5b6000610bb084828501610b77565b91505092915050565b6000604082019050610bce6000830185610a74565b610bdb6020830184610a83565b9392505050565b60007fffffff000000000000000000000000000000000000000000000000000000000082169050919050565b610c1781610be2565b82525050565b6000606082019050610c326000830186610c0e565b610c3f6020830185610a83565b610c4c6040830184610a83565b949350505050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610c7f82610c54565b9050919050565b60008160601b9050919050565b6000610c9e82610c86565b9050919050565b6000610cb082610c93565b9050919050565b610cc8610cc382610c74565b610ca5565b82525050565b6000610cda8284610cb7565b6014820191508190509291505056fea26469706673582212206db81ea021e8bb34c2493b1b00c2d863cb9a41d52445db94757d5035b44b00f464736f6c63430008130033"}

    some_other_deployed_contract = get_contract(web3, some_other_contract_keeping_data['abi'],
                                                some_other_contract_keeping_data['bytecode'],
                                                some_other_contract_keeping_data['address'])

    old_network_encrypted_data = get_network_value(deployed_contract, eoa)
    network_encrypted_data = get_network_value(some_other_deployed_contract, eoa)
    save_network_encrypted_in_contract(deployed_contract, tx_params, network_encrypted_data)
    new_network_encrypted_data = get_network_value(deployed_contract, eoa)
    # assert that previous data and new one are not the same, meaning it was really changed
    assert old_network_encrypted_data != new_network_encrypted_data
    # assert that new data is same as the one we copied it from
    assert new_network_encrypted_data == network_encrypted_data
    tx_receipt = save_network_encrypted_to_user_encrypted_in_contract(deployed_contract, tx_params)
    # assert that it failed to save network encrypted data into user encrypted data, that was actually copied from
    # another contract, hence, keeping different contracts secured
    assert tx_receipt.status == 0


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
    tx_receipt = save_network_encrypted_to_user_encrypted_in_contract(deployed_contract, tx_params)
    user_encrypted_value_from_block = tx_receipt.logs[0].data
    user_encrypted_value_from_block_int_value = int(user_encrypted_value_from_block.hex(), 16)
    user_encrypted_value_from_contract = get_user_encrypted_from_contract(deployed_contract, eoa)
    # assert that same value back from view func is one back from event
    assert user_encrypted_value_from_block_int_value == user_encrypted_value_from_contract
    user_some_value_decrypted = decrypt_value(user_encrypted_value_from_contract, account_hex_encryption_key)
    # assert that value saved encrypted within the network is one sent
    assert user_some_value_decrypted == user_some_value_clear
    return user_some_value_decrypted


def save_network_encrypted_to_user_encrypted_in_contract(deployed_contract, tx_params):
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


def save_network_encrypted_in_contract(deployed_contract, tx_params, value):
    kwargs = {'networkEncrypted': value}
    tx_receipt = setNetworkSomeEncryptedValue(deployed_contract, kwargs, tx_params)
    print(tx_receipt)


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


def setNetworkSomeEncryptedValue(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.setNetworkSomeEncryptedValue(**kwargs)
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
