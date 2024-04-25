from dotenv import load_dotenv

from utils import *


# Script transfers native funds from wallet account to random one
def main():
    load_dotenv()  # loading .env
    eoa_private_key = get_account_private_key()  # Get EOA Private key for execution
    eoa = get_eoa(eoa_private_key)  # Get EOA
    web3 = init_web3(get_node_https_address(), eoa)  # Init connection to node
    validate_minimum_balance(web3)  # validate minimum balance

    alice_address = Account.create()  # create some random address to transfer funds into
    amount_to_transfer_ether = 0.000000005
    num_of_gas_units = 21000

    tx_receipt = transfer_native(web3, alice_address.address, eoa_private_key, amount_to_transfer_ether,
                                 num_of_gas_units)
    print(tx_receipt)


if __name__ == "__main__":
    main()
