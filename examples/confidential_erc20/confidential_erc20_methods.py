from examples.basics.utils import *


def approve(deployed_contract, kwargs, plaintext_integer, account_hex_encryption_key, eoa, tx_params):
    eoa_private_key = tx_params['eoa_private_key']
    func = deployed_contract.functions.approve(**kwargs)
    func_sig = get_function_signature(func.abi)
    hex_account_private_key = bytes.fromhex(eoa_private_key)
    ct, signature = build_input_text(plaintext_integer, account_hex_encryption_key, eoa, deployed_contract, func_sig,
                                     hex_account_private_key)
    kwargs['_itCT'] = ct
    kwargs['_itSignature'] = signature
    func = deployed_contract.functions.approve(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def get_account_balance(account_hex_encryption_key, deployed_contract, eoa):
    cipher_text_balance = deployed_contract.functions.balanceOf().call({'from': eoa.address})
    account_balance = decrypt_value(cipher_text_balance, account_hex_encryption_key)
    return account_balance


def approveClear(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.approveClear(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def transfer_from_clear(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.contractTransferFromClear(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def transfer_from(deployed_contract, kwargs, eoa, account_hex_encryption_key, plaintext_integer, tx_params):
    account_private_key = eoa.key.hex()[2:]  # tx_params['eoa_private_key']
    func = deployed_contract.functions.transferFrom(**kwargs)
    func_sig = get_function_signature(func.abi)
    hex_account_private_key = bytes.fromhex(account_private_key)
    ct, signature = build_input_text(plaintext_integer, account_hex_encryption_key, eoa, deployed_contract, func_sig,
                                     hex_account_private_key)
    kwargs['_itCT'] = ct
    kwargs['_itSignature'] = signature
    func = deployed_contract.functions.transferFrom(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def transfer_encrypted(deployed_contract, kwargs, eoa, account_hex_encryption_key, tx_params):
    eoa_private_key = tx_params['eoa_private_key']
    plaintext_integer = kwargs['_itCT']
    func = deployed_contract.functions.transfer(**kwargs)
    func_sig = get_function_signature(func.abi)
    hex_account_private_key = bytes.fromhex(eoa_private_key)
    ct, signature = build_input_text(plaintext_integer, account_hex_encryption_key, eoa, deployed_contract, func_sig,
                                     hex_account_private_key)
    kwargs['_itCT'] = ct
    kwargs['_itSignature'] = signature
    func = deployed_contract.functions.transfer(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def transfer_clear(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.contractTransferClear(**kwargs)
    return exec_func_via_transaction(func, tx_params)


def transfer(deployed_contract, kwargs, tx_params):
    func = deployed_contract.functions.transfer(**kwargs)
    return exec_func_via_transaction(func, tx_params)
