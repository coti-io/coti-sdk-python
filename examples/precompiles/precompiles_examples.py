from dotenv import load_dotenv

from examples.basics.utils import *

contracts = {}
last_random_value = 0


# Script demonstrates example for COTI v2 operations possible via precompiles actions
def load_contracts(tx_params):
    contracts_sol_list = glob.glob(get_contracts_working_directory() + "examples/precompiles/*.sol")
    relative_to_mpc_core = "../../lib/MpcCore.sol"
    assert len(contracts_sol_list) != 0
    for contract_sol in contracts_sol_list:
        contract_file_name = os.path.basename(contract_sol)
        contract_name = contract_file_name.replace(".sol", "")
        sols = get_sols(os.path.dirname(contract_sol), contract_file_name)
        deployed_contract, was_already_deployed = \
            get_deployed_contract(contract_name, contract_file_name, tx_params, sols, relative_to_mpc_core)
        contracts.update({contract_name: deployed_contract})


def get_deployed_contract(contract_name, contract_file_name, tx_params, sols, relative_to_mpc_core):
    already_deployed, deployed_contract_file_name = is_contract_already_deployed(contract_name)
    if not already_deployed:
        kwargs = {}
        deploy_and_save(contract_name, contract_file_name, kwargs, tx_params, sols, relative_to_mpc_core)
        _, deployed_contract_file_name = is_contract_already_deployed(contract_name)
    web3 = tx_params['web3']
    deployed_contract = load_contract_from_file(deployed_contract_file_name, web3)
    return deployed_contract, already_deployed


def get_contract_implementing_function(function_name):
    for contract in contracts:
        abi = contracts[contract].abi
        has_func = (str(abi).__contains__(function_name))
        if has_func:
            return contracts[contract]


def test_user_key(function_name, kwargs, expected_result1, get_result_function_name, tx_params, expected_result2=None,
                  expected_result3=None, expected_result4=None):
    private_key, public_key = generate_rsa_keypair()
    signedEK = sign(public_key, bytes.fromhex("2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"))
    contract = get_contract_implementing_function("userKeyTest")
    func = getattr(contract.functions, "userKeyTest")
    workaround = func.w3.eth.default_account
    func.w3.eth.default_account = func.w3.eth.default_account.address
    encrypted_user_key = func(*[public_key, signedEK]).call()
    func.w3.eth.default_account = workaround
    decrypted_aes_key = decrypt_rsa(private_key, encrypted_user_key)
    result1, result2, result3, result4 = test(function_name, kwargs, expected_result1, get_result_function_name,
                                              tx_params)
    assert decrypt_value(result1, decrypted_aes_key) == expected_result1
    assert decrypt_value(result2, decrypted_aes_key) == expected_result1
    assert decrypt_value(result3, decrypted_aes_key) == expected_result1
    assert decrypt_value(result4, decrypted_aes_key) == expected_result1


def test(function_name, kwargs, expected_result1, get_result_function_name, tx_params, expected_result2=None,
         expected_result3=None, expected_result4=None, expected_result5=None, expected_result6=None,
         expected_result7=None, expected_result8=None):
    global last_random_value
    contract = get_contract_implementing_function(function_name)
    func = contract.functions[function_name](**kwargs)
    tx_receipt = exec_func_via_transaction(func, tx_params)
    print(tx_receipt)
    result1, result2, result3, result4, result5, result6, result7, result8 \
        = get_result(contract, get_result_function_name)
    if function_name == "transferTest" or function_name == "transferScalarTest":
        assert result1 == expected_result1
        assert result2 == expected_result2
        assert result3
        return
    if function_name == "offboardToUserTest":
        return result1, result2, result3, result4
    if get_result_function_name == "getRandom":
        assert result1 != expected_result1
        last_random_value = result1
        return
    assert result1 == expected_result1
    assert result2 == expected_result2
    assert result3 == expected_result3
    assert result4 == expected_result4
    assert result5 == expected_result5
    assert result6 == expected_result6
    assert result7 == expected_result7
    assert result8 == expected_result8


def get_result(contract, get_result_function_name):
    func = getattr(contract.functions, get_result_function_name)
    workaround = func.w3.eth.default_account
    func.w3.eth.default_account = func.w3.eth.default_account.address
    results = func(*[]).call()
    func.w3.eth.default_account = workaround
    if type(results) is list:
        diff = 8 - len(results)
        for i in range(0, diff):
            results.append(None)
        return results
    return results, None, None, None, None, None, None, None


def run_tests(a, b, shift, bit, numBits, bool_a, bool_b, tx_params):
    test("addTest", {'a': a, 'b': b}, a + b, "getResult", tx_params)
    test("subTest", {'a': a, 'b': b}, a - b, "getResult", tx_params)
    test("mulTest", {'a': a, 'b': b}, a * b, "getResult16", tx_params)
    test("divTest", {'a': a, 'b': b}, a / b, "getResult", tx_params)
    test("remTest", {'a': a, 'b': b}, a % b, "getResult", tx_params)
    test("andTest", {'a': a, 'b': b}, a & b, "getResult", tx_params)
    test("orTest", {'a': a, 'b': b}, a | b, "getResult", tx_params)
    test("xorTest", {'a': a, 'b': b}, a ^ b, "getResult", tx_params)
    test("xorTest", {'a': a, 'b': b}, a ^ b, "getResult", tx_params)
    test("shlTest", {'a': a, 'b': shift}, (a << shift) & 0xFF, "getAllShiftResults",
         tx_params, (a << shift) & 0xFFFF, (a << shift) & 0xFFFFFFFF, (a << shift) & 0xFFFFFFFFFFFFFFFF)
    test("shrTest", {'a': a, 'b': shift}, a >> shift, "getResult", tx_params)
    test("minTest", {'a': a, 'b': b}, min(a, b), "getResult", tx_params)
    test("maxTest", {'a': a, 'b': b}, max(a, b), "getResult", tx_params)
    test("eqTest", {'a': a, 'b': b}, a == b, "getResult", tx_params)
    test("neTest", {'a': a, 'b': b}, a != b, "getResult", tx_params)
    test("geTest", {'a': a, 'b': b}, a >= b, "getResult", tx_params)
    test("gtTest", {'a': a, 'b': b}, a > b, "getResult", tx_params)
    test("leTest", {'a': a, 'b': b}, a <= b, "getResult", tx_params)
    test("ltTest", {'a': a, 'b': b}, a < b, "getResult", tx_params)
    test("muxTest", {'selectionBit': bit, 'a': a, 'b': b}, a if bit == 0 else b, "getResult", tx_params)
    test("transferTest", {'amount': b, 'a': a, 'b': b}, a - b, "getResults", tx_params, b + b)
    test("transferScalarTest", {'amount': b, 'a': a, 'b': b}, a - b, "getResults", tx_params, b + b)
    test("offboardOnboardTest", {'a8': a, 'a16': a, 'a32': a, 'a64': a}, a, "getResult", tx_params)
    test("notTest", {'a': bit}, not bit, "getBoolResult", tx_params)
    test_user_key("offboardToUserTest", {'a': a, 'addr': tx_params['web3'].eth.default_account.address},
                  a, "getCTs", tx_params)
    test("randomTest", {}, last_random_value, "getRandom", tx_params)
    test("randomBoundedTest", {'numBits': numBits}, last_random_value, "getRandom", tx_params)
    test("booleanTest", {"a": bool_a, "b": bool_b, "bit": bit}, bool_a and bool_b,
         "getBooleanResults", tx_params, bool_a or bool_b, bool_a ^ bool_b, not bool_a,
         bool_a == bool_b, bool_a != bool_b, bool_b if bit else bool_a, bool_a)


def main():
    load_dotenv()
    print("Running pre-compiles example testing...")
    eoa_private_key, web3 = init()

    gas_limit = 15598400
    gas_price_gwei = 30
    tx_params = {'web3': web3, 'gas_limit': gas_limit, 'gas_price_gwei': gas_price_gwei,
                 'eoa_private_key': eoa_private_key}
    load_contracts(tx_params)
    run_tests(10, 5, 2, False, 7, True, False, tx_params)


def init():
    load_dotenv()  # loading .env
    eoa_private_key = get_account_private_key()  # Get EOA Private key for execution
    eoa = get_eoa(eoa_private_key)  # Get EOA
    web3 = init_web3(get_node_https_address(), eoa)  # Init connection to node
    validate_minimum_balance(web3)  # validate minimum balance
    return eoa_private_key, web3


if __name__ == "__main__":
    main()
