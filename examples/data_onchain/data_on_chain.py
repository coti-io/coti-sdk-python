from examples.onboard.onboard_account import *


# script demonstrates basic network capabilities on encrypt/decrypt of values saved in a contract
def main():
    account_hex_encryption_key, eoa, eoa_private_key, web3 = init()

    gas_limit = 10000000
    gas_price_gwei = 30

    tx_params = {'web3': web3, 'gas_limit': gas_limit, 'gas_price_gwei': gas_price_gwei,
                 'eoa_private_key': eoa_private_key}
    deployed_contract = deploy(account_hex_encryption_key, eoa, tx_params)

    basic_get_value(deployed_contract, eoa, web3)
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
                                        "address": "0x074695f49d9c788c056FbBc697669EE6F23AE796",
                                        "abi": [{"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
                                                {"anonymous": false, "inputs": [
                                                    {"indexed": true, "internalType": "address", "name": "_from",
                                                     "type": "address"}, {"indexed": false, "internalType": "ctUint64",
                                                                          "name": "ctUserSomeEncryptedValue",
                                                                          "type": "uint256"}],
                                                 "name": "UserEncryptedValue", "type": "event"},
                                                {"inputs": [], "name": "add", "outputs": [],
                                                 "stateMutability": "nonpayable", "type": "function"},
                                                {"inputs": [], "name": "getNetworkSomeEncryptedValue", "outputs": [
                                                    {"internalType": "ctUint64", "name": "ctSomeEncryptedValue",
                                                     "type": "uint256"}], "stateMutability": "view",
                                                 "type": "function"},
                                                {"inputs": [], "name": "getNetworkSomeEncryptedValueEncryptedInput",
                                                 "outputs": [
                                                     {"internalType": "ctUint64", "name": "ctSomeEncryptedValue",
                                                      "type": "uint256"}], "stateMutability": "view",
                                                 "type": "function"}, {"inputs": [], "name": "getSomeValue",
                                                                       "outputs": [
                                                                           {"internalType": "uint64", "name": "value",
                                                                            "type": "uint64"}],
                                                                       "stateMutability": "view", "type": "function"},
                                                {"inputs": [], "name": "getUserArithmeticResult", "outputs": [
                                                    {"internalType": "ctUint64", "name": "value", "type": "uint256"}],
                                                 "stateMutability": "view", "type": "function"},
                                                {"inputs": [], "name": "getUserSomeEncryptedValue", "outputs": [
                                                    {"internalType": "ctUint64", "name": "ctSomeEncryptedValue",
                                                     "type": "uint256"}], "stateMutability": "view",
                                                 "type": "function"},
                                                {"inputs": [], "name": "getUserSomeEncryptedValueEncryptedInput",
                                                 "outputs": [
                                                     {"internalType": "ctUint64", "name": "ctSomeEncryptedValue",
                                                      "type": "uint256"}], "stateMutability": "view",
                                                 "type": "function"}, {"inputs": [
                                                {"internalType": "ctUint64", "name": "networkEncrypted",
                                                 "type": "uint256"}], "name": "setNetworkSomeEncryptedValue",
                                                                       "outputs": [], "stateMutability": "nonpayable",
                                                                       "type": "function"}, {"inputs": [
                                                {"internalType": "uint64", "name": "_value", "type": "uint64"}],
                                                                                             "name": "setSomeEncryptedValue",
                                                                                             "outputs": [],
                                                                                             "stateMutability": "nonpayable",
                                                                                             "type": "function"}, {
                                                    "inputs": [{"internalType": "ctUint64", "name": "_itCT",
                                                                "type": "uint256"},
                                                               {"internalType": "bytes", "name": "_itSignature",
                                                                "type": "bytes"}],
                                                    "name": "setSomeEncryptedValueEncryptedInput", "outputs": [],
                                                    "stateMutability": "nonpayable", "type": "function"},
                                                {"inputs": [], "name": "setUserSomeEncryptedValue", "outputs": [],
                                                 "stateMutability": "nonpayable", "type": "function"},
                                                {"inputs": [], "name": "setUserSomeEncryptedValueEncryptedInput",
                                                 "outputs": [], "stateMutability": "nonpayable", "type": "function"}],
                                        "bytecode": "0x608060405234801561001057600080fd5b5060056000806101000a81548167ffffffffffffffff021916908367ffffffffffffffff160217905550610d7d806100496000396000f3fe608060405234801561001057600080fd5b50600436106100b45760003560e01c80638d7eadec116100715780638d7eadec146101435780639c82c7c714610161578063a2e128691461017d578063a40674b71461019b578063af384ac7146101b9578063fee511d6146101d5576100b4565b806305bdf1db146100b957806318312545146100d75780634f0bc491146100f55780634f2be91f1461011157806361eeffcd1461011b57806371091de314610125575b600080fd5b6100c16101df565b6040516100ce919061089d565b60405180910390f35b6100df6101e9565b6040516100ec919061089d565b60405180910390f35b61010f600480360381019061010a9190610953565b6101f3565b005b610119610275565b005b6101236102b6565b005b61012d610328565b60405161013a919061089d565b60405180910390f35b61014b610332565b604051610158919061089d565b60405180910390f35b61017b600480360381019061017691906109b3565b61033c565b005b610185610346565b604051610192919061089d565b60405180910390f35b6101a3610350565b6040516101b09190610a03565b60405180910390f35b6101d360048036038101906101ce9190610a4a565b61036d565b005b6101dd61038d565b005b6000600354905090565b6000600154905090565b6101fb61083e565b8381600001818152505082828080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050508160200181905250600061025d826103ff565b9050610268816104a6565b6004819055505050505050565b6000610282600354610543565b90506000610291600454610543565b9050600061029f83836105e0565b90506102ab8133610677565b600581905550505050565b60006102c3600454610543565b90506102cf8133610677565b6002819055503373ffffffffffffffffffffffffffffffffffffffff167f958094500e56c659b01cdefb25c66c88f025c3c800f69b2a2141f8c73b30e05660025460405161031d919061089d565b60405180910390a250565b6000600454905090565b6000600554905090565b8060038190555050565b6000600254905090565b60008060009054906101000a900467ffffffffffffffff16905090565b600061037882610736565b9050610383816104a6565b6003819055505050565b600061039a600354610543565b90506103a68133610677565b6001819055503373ffffffffffffffffffffffffffffffffffffffff167f958094500e56c659b01cdefb25c66c88f025c3c800f69b2a2141f8c73b30e0566001546040516103f4919061089d565b60405180910390a250565b6000606473ffffffffffffffffffffffffffffffffffffffff1663e4f36e1060048081111561043157610430610a77565b5b60f81b846000015185602001516040518463ffffffff1660e01b815260040161045c93929190610b80565b6020604051808303816000875af115801561047b573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061049f9190610bea565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663c50c9c026004808111156104d8576104d7610a77565b5b60f81b846040518363ffffffff1660e01b81526004016104f9929190610c17565b6020604051808303816000875af1158015610518573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061053c9190610bea565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d2c135e560048081111561057557610574610a77565b5b60f81b846040518363ffffffff1660e01b8152600401610596929190610c17565b6020604051808303816000875af11580156105b5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906105d99190610bea565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16638c5d015061060c60048060006107dd565b85856040518463ffffffff1660e01b815260040161062c93929190610c7b565b6020604051808303816000875af115801561064b573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061066f9190610bea565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e686004808111156106a9576106a8610a77565b5b60f81b85856040516020016106be9190610d2c565b6040516020818303038152906040526040518463ffffffff1660e01b81526004016106eb93929190610b80565b6020604051808303816000875af115801561070a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061072e9190610bea565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b6060048081111561076857610767610a77565b5b60f81b8467ffffffffffffffff166040518363ffffffff1660e01b8152600401610793929190610c17565b6020604051808303816000875af11580156107b2573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906107d69190610bea565b9050919050565b60008160028111156107f2576107f1610a77565b5b60ff16600884600481111561080a57610809610a77565b5b61ffff16901b61ffff16601086600481111561082957610828610a77565b5b62ffffff16901b171760e81b90509392505050565b604051806040016040528060008152602001606081525090565b6000819050919050565b6000819050919050565b600061088761088261087d84610858565b610862565b610858565b9050919050565b6108978161086c565b82525050565b60006020820190506108b2600083018461088e565b92915050565b600080fd5b600080fd5b6108cb81610858565b81146108d657600080fd5b50565b6000813590506108e8816108c2565b92915050565b600080fd5b600080fd5b600080fd5b60008083601f840112610913576109126108ee565b5b8235905067ffffffffffffffff8111156109305761092f6108f3565b5b60208301915083600182028301111561094c5761094b6108f8565b5b9250929050565b60008060006040848603121561096c5761096b6108b8565b5b600061097a868287016108d9565b935050602084013567ffffffffffffffff81111561099b5761099a6108bd565b5b6109a7868287016108fd565b92509250509250925092565b6000602082840312156109c9576109c86108b8565b5b60006109d7848285016108d9565b91505092915050565b600067ffffffffffffffff82169050919050565b6109fd816109e0565b82525050565b6000602082019050610a1860008301846109f4565b92915050565b610a27816109e0565b8114610a3257600080fd5b50565b600081359050610a4481610a1e565b92915050565b600060208284031215610a6057610a5f6108b8565b5b6000610a6e84828501610a35565b91505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60007fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b610adb81610aa6565b82525050565b610aea81610858565b82525050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610b2a578082015181840152602081019050610b0f565b60008484015250505050565b6000601f19601f8301169050919050565b6000610b5282610af0565b610b5c8185610afb565b9350610b6c818560208601610b0c565b610b7581610b36565b840191505092915050565b6000606082019050610b956000830186610ad2565b610ba26020830185610ae1565b8181036040830152610bb48184610b47565b9050949350505050565b610bc781610858565b8114610bd257600080fd5b50565b600081519050610be481610bbe565b92915050565b600060208284031215610c0057610bff6108b8565b5b6000610c0e84828501610bd5565b91505092915050565b6000604082019050610c2c6000830185610ad2565b610c396020830184610ae1565b9392505050565b60007fffffff000000000000000000000000000000000000000000000000000000000082169050919050565b610c7581610c40565b82525050565b6000606082019050610c906000830186610c6c565b610c9d6020830185610ae1565b610caa6040830184610ae1565b949350505050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610cdd82610cb2565b9050919050565b60008160601b9050919050565b6000610cfc82610ce4565b9050919050565b6000610d0e82610cf1565b9050919050565b610d26610d2182610cd2565b610d03565b82525050565b6000610d388284610d15565b6014820191508190509291505056fea2646970667358221220650fb0fb3db867c1b25dafd54d04e2a06e432c4f34a3eae897807648c788499a64736f6c63430008130033"}
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
def basic_get_value(deployed_contract, eoa, web3):
    some_value = deployed_contract.functions.getSomeValue().call({'from': eoa.address})
    assert some_value == 5
    index_0_at_storage = int(web3.eth.get_storage_at(deployed_contract.address, 0).hex(), 16)
    assert index_0_at_storage == 5


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
