# COTI v2 Python SDK

The COTI Python SDK is comprised of two main components:

1. Python libraries (located in `/lib`): The libraries allow you to interact with the COTI network to carry out operations such as creating keys and encrypting/decrypting data.
2. Python script examples (located in `/examples`): the examples folder contain scripts that perform various various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and Identity management. It contains smart contracts that implement confidentiality features using the COTI V2 protocol. 

These contracts demonstrate how to leverage the confidentiality features of the COTI V2 protocol to enhance privacy and security in decentralized applications.

The contracts are written in Solidity and can be compiled and deployed using popular development frameworks such as Hardhat and Foundry.

The following example contracts are available in the Python SDK for deployment and execution:

| Contract       | Contract Description                                                                                                                          |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| AccountOnboard | Onboard a EOA account - During onboard network creates AES unique for that EOA which is used for decrypting values sent back from the network |
| ERC20Example   | Confidential ERC20 - deploy and transfer encrypted amount of funds                                                                            |
| DataOnChain    | Basic encryption and decryption - Good place to start explorining network capabilties                                                         |
| Precompile     | Thorough examples of the precompile functionality                                                                                             |

> [!NOTE]  
> Due to the nature of ongoing development, future versions might break existing functionality

## Getting initial funds from the COTI Faucet

The COTI faucet provides devnet/testnet funds for developers. To request devnet/testnet tokens:

1. Head to https://faucet.coti.io/
2. Send a message to the bot in the following format: 

```
devnet <your_eoa_address> 
```

For Example:

```
devnet 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
```

## Python SDK Usage

The sample contracts described above reside in the [coti-sdk-python/examples](/examples/) directory. The solidity contracts are in the [confidentiality-contracts](/confidentiality-contracts/) directory which is imported as a git submodule.

When a script executed (for example `data_on_chain.py`) it will deploy the contract and create a json file with the details of the deployed
contract under the `/compiled_contracts` directory.

Inspect the `.env` file for more details.

The python examples utilizes primitive deployment management that mostly checks if there is a json file under the `/compiled_contracts` directory
and doesn't deploy a new one in case one already exists, otherwise it deploys.

### Getting Started

1. Generate EOA: Run the `native_transfer.py` script, it will transfer tiny amount to some random address - demonstrating standard native transfer.
   It will create a new EOA (you will see your public address in the script output), and the account private key will be recorded in your `.env` file.
   It will fail on first run since the account doesn't have any funds. Refer to the Faucet section above

2. Generate Encryption Key: Run the `onboard_account.py` script, it will ask the network for the AES encryption key specific for this account and
   it will log it in the `.env` file (mandatory for every action that performs COTI v2 onchain computation).

3. Execute: Now you can run any other example, such as `precompiles_examples.py` (see above for complete list).

In order to follow the transactions sent to the node, use the `web_socket.py` to be notified and see on-chain details.

## Libraries

There are two libraries located in the [libs](/libs/) folder that will allow you to interact with the COTI network.

### Crypto Utilities (crypto_utils.py)

#### Functions

1. `encrypt(key, plaintext)`

      **Purpose:**  
      Encrypts a plaintext message using AES encryption with a provided key.

      **Usage:**
      ```python
      ciphertext, r = encrypt(key, plaintext)
      ```

      **Parameters:**
      - **key**: A 128-bit (16-byte) AES key.
      - **plaintext**: The plaintext message to be encrypted. Must be 128 bits (16 bytes) or smaller.

2. `decrypt(key, r, ciphertext)`

      **Purpose:**
      Decrypts a ciphertext message using AES decryption with a provided key and random value.

      **Usage:**
      ```python
      plaintext = decrypt(key, r, ciphertext)
      ```

      **Parameters:**
      - **key**: A 128-bit (16-byte) AES key.
      - **r**: The random value used during encryption.
      - **ciphertext**: The encrypted message to be decrypted.


## Pending enhancements
* Versioned pypi library
* Extending examples such as confidential ERC20 minting, confidential NFT (deployment and actions) and more.

#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-python/issues)

