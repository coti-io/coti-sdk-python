import glob
import json

import dotenv
from solcx import get_installed_solc_versions, install_solc, compile_standard

from libs.utils import *


def get_sols(contract_directory, contract_file_name):
    sols = {
        contract_file_name: {"urls": [str(contract_directory) + "/" + contract_file_name]},
    }
    return sols


def get_node_https_address():
    node_https_address = os.getenv('NODE_HTTPS_ADDRESS')
    return node_https_address


def get_node_wss_address():
    node_wss_address = os.getenv('NODE_WSS_ADDRESS')
    return node_wss_address


def create_eoa():
    account = Account.create()
    hex_val = account._private_key.hex()
    dotenv.set_key(get_working_directory() + '/.env', 'ACCOUNT_PRIVATE_KEY', hex_val)
    return hex_val


def get_account_private_key():
    account_private_key = os.getenv('ACCOUNT_PRIVATE_KEY')
    if account_private_key is None:
        print('So you dont have an account yet, dont worry... lets create one right now!')
        account_private_key = create_eoa()
        print('Creation done!')
    if account_private_key.startswith('0x'):
        account_private_key = account_private_key[2:]
    return account_private_key


def get_compiled_contracts_dir():
    compiled_contracts_dir = get_contracts_working_directory() + '/' + os.getenv('COMPILED_CONTRACTS_DIR') + '/'
    return compiled_contracts_dir


def is_devnet():
    return os.getenv('ENV').lower() == 'devnet'


def get_hex_account_encryption_key():
    set_hex_account_encryption = os.getenv('ACCOUNT_ENCRYPTION_KEY')
    if set_hex_account_encryption is None:
        raise Exception('Account is not onboarded - there is no user key in network, execute onboard_account.py')
    return bytes.fromhex(set_hex_account_encryption)


def set_hex_account_encryption_key(val):
    return dotenv.set_key(get_working_directory() + "/.env", "ACCOUNT_ENCRYPTION_KEY", val)


def validate_minimum_balance(web3):
    balance = get_native_balance(web3)
    if balance == 0:
        if is_devnet():
            raise Exception("Not enough balance!, head to discord faucet and getsome...")
        raise Exception("Not enough balance!")


def is_contract_already_deployed(contract_name):
    compiled_contracts_dir = get_compiled_contracts_dir()
    contract_json_list = glob.glob(
        os.path.dirname(compiled_contracts_dir) + "/" + contract_name + "*.json")
    if len(contract_json_list) > 0:
        return True, contract_json_list[0]
    return False, None


def get_deployed_contract(contract_name, contract_file_name, contract_directory, tx_params, kwargs,
                          relative_to_mpc_core):
    web3 = tx_params['web3']
    already_deployed, deployed_contract_file_name = is_contract_already_deployed(contract_name)
    if not already_deployed:
        sols = get_sols(get_contracts_working_directory() + contract_directory, contract_file_name)
        deploy_and_save(contract_name, contract_file_name, kwargs, tx_params, sols, relative_to_mpc_core)
        _, deployed_contract_file_name = is_contract_already_deployed(contract_name)
    deployed_contract = load_contract_from_file(deployed_contract_file_name, web3)
    return deployed_contract, already_deployed


def load_contract_from_file(deployed_contract_file_name, web3):
    with open(deployed_contract_file_name, 'r') as f:
        dumped_contract = json.loads(f.readlines()[0])
    contract_address = dumped_contract['address']
    return get_contract(web3, dumped_contract['abi'], dumped_contract['bytecode'], contract_address)


def get_contract(web3, abi, bytecode, contract_address):
    deployed_contract = web3.eth.contract(address=contract_address, abi=abi, bytecode=bytecode)
    return deployed_contract


def deploy_and_save(contract_name, contract_file_name, kwargs, tx_params, sols, relative_to_mpc_core):
    web3 = tx_params['web3']
    print(f"Compiling {contract_name}...")
    contract = compile_contract(contract_name, contract_file_name, web3, sols, relative_to_mpc_core)
    print(f"Deploying {contract_name}...")
    tx_receipt = deploy_contract(contract, kwargs, tx_params)
    print("Contract deployed at address:", tx_receipt.contractAddress)
    dumped_contract = {"contract_name": contract_name,
                       "address": tx_receipt.contractAddress,
                       "abi": contract.abi,
                       "bytecode": contract.bytecode.hex()}
    if not os.path.exists(get_compiled_contracts_dir()):
        os.mkdir(get_compiled_contracts_dir())
    with open(get_compiled_contracts_dir() + contract_name + '_' + tx_receipt.contractAddress + '.json', 'w') as f:
        json.dump(dumped_contract, f)


def get_working_directory():
    repo_name = 'coti-sdk-python'
    working_dir = os.getcwd()
    working_dir = working_dir[:working_dir.find(repo_name) + len(repo_name)]
    return working_dir


def get_contracts_working_directory():
    project_name = os.getenv('SOLIDITY_CONTRACTS_DIR')

    working_dir = os.getcwd()
    if not working_dir.endswith('/'):
        working_dir = working_dir + '/'
    if working_dir.endswith(project_name) or working_dir.endswith(project_name + '/'):
        return working_dir
    else:
        raise Exception("contracts examples should be executed in root of " + project_name)


def compile_contract(contract_name, contract_file_name, web3, sols, relative_to_mpc_core):
    if SOLC_VERSION not in get_installed_solc_versions():
        install_solc(SOLC_VERSION)

    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": sols,
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                }
            }
        },
    },
        solc_version=SOLC_VERSION,
        allow_paths=[relative_to_mpc_core]
    )

    bytecode = compiled_sol['contracts'][contract_file_name][contract_name]['evm']['bytecode']['object']
    contract_abi = json.loads(compiled_sol['contracts'][contract_file_name][contract_name]['metadata'])['output']['abi']
    contract_bytecode = f'0x{bytecode}'
    return web3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
