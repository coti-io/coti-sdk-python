# COTI V2 Confidentiality Preserving L2 | SDKs and Examples

All repositories specified below contain smart contracts that implement confidentiality features using the COTI V2
protocol.
The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and
Identity management.

These contracts demonstrate how to leverage the confidentiality features of the COTI V2 protocol to enhance privacy and
security in decentralized applications.
The contracts are written in Solidity and can be compiled and deployed using popular development tools like Hardhat and
Foundry.

#### Important Links:

[Docs](https://docs.coti.io) | [Devnet Explorer](https://explorer-devnet.coti.io) | [Discord](https://discord.gg/cuCykh8P4m) | [Faucet](https://faucet.coti.io)

Interact with the network using any of the following:

1. [Python SDK](https://github.com/coti-io/coti-sdk-python) | [Python SDK Examples](https://github.com/coti-io/coti-sdk-python-examples)
2. [Typescript SDK](https://github.com/coti-io/coti-sdk-typescript) | [Typescript SDK Examples](https://github.com/coti-io/coti-sdk-typescript-examples)
3. [Hardhat Dev Environment](https://github.com/coti-io/confidentiality-contracts)

The following contracts are available in each of the packages:

| Contract                       |            | python sdk | hardhat sdk | typescript sdk | Contract Description                                                                                                                          |
|--------------------------------|------------|------------|-------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `AccountOnboard`               | deployment | ✅ *        | ✅           | ❌              | Onboard a EOA account - During onboard network creates AES unique for that EOA which is used for decrypting values sent back from the network |
| `AccountOnboard`               | execution  | ✅          | ✅           | ✅              | "                                                                                                                                             |
| `ERC20Example`                 | deployment | ✅          | ✅           | ❌              | Confidential ERC20 - deploy and transfer encrypted amount of funds                                                                            |
| `ERC20Example`                 | execution  | ✅          | ✅           | ✅              | "                                                                                                                                             |
| `NFTExample`                   | deployment | ❌          | ✅           | ❌              | Confidential NFT example - saving encrypted data                                                                                              |
| `NFTExample`                   | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `ConfidentialAuction`          | deployment | ❌          | ✅           | ❌              | Confidential auction - encrypted bid amount                                                                                                   |
| `ConfidentialAuction`          | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `ConfidentialIdentityRegistry` | deployment | ❌          | ✅           | ❌              | Confidential Identity Registry - Encrypted identity data                                                                                      |
| `ConfidentialIdentityRegistry` | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `DataOnChain`                  | deployment | ✅          | ❌           | ❌              | Basic encryption and decryption - Good place to start explorining network capabilties                                                         |
| `DataOnChain`                  | execution  | ✅          | ❌           | ✅              | "                                                                                                                                             |
| `Precompile`                   | deployment | ✅          | ✅           | ❌              | Thorough examples of the precompile functionality                                                                                             |
| `Precompile`                   | execution  | ✅          | ✅           | ❌              | "                                                                                                                                             |-              |              

(*) no deployment needed (system contract)

> [!NOTE]  
> Due to the nature of ongoing development, future versions might break existing functionality

### Faucet

🤖 To request devnet/testnet funds use
our [faucet](https://faucet.coti.io) ([join discord] (https://discord.gg/cuCykh8P4m)))

# COTI v2 Python SDK

> [!NOTE]
> Please refer to the latest [tags](https://github.com/coti-io/coti-sdk-python/tags) to find the most stable version to
> use.
> All tagged versions are available to install via [pypi](https://pypi.org/project/coti-sdk/)

The COTI Python SDK can be installed as pypi package named `coti_sdk`, its modules are:

1. `crypto_utils`: used for cryptographic operations
2. `utils` : used for web3 related operations

The [Python script examples](https://github.com/coti-io/coti-sdk-python-examples) project contain scripts covering
various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auctions, and Identity management. It contains
smart contracts that implement confidentiality features using the COTI V2 protocol. These contracts demonstrate how to
leverage the confidentiality features of the COTI V2 protocol to implement privacy and enhance security in decentralized
applications.

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

## Libraries

There are two libraries located in the [coti](/coti/) folder that will allow you to interact with the COTI network.

# Crypto Utilities (crypto_utils.py)
## Functions

### `encrypt(key, plaintext)`

Encrypts a 128-bit `plaintext` using the provided 128-bit AES `key` and ECB mode.

- **Parameters:**
  - `key (bytes)`: 128-bit AES key (16 bytes).
  - `plaintext (bytes)`: 128-bit or smaller plaintext to encrypt.

- **Returns:**
  - `ciphertext (bytes)`: The encrypted text.
  - `r (bytes)`: A random value used during encryption.

### `decrypt(key, r, ciphertext)`

Decrypts the `ciphertext` using the provided 128-bit AES `key` and the random value `r`.

- **Parameters:**
  - `key (bytes)`: 128-bit AES key.
  - `r (bytes)`: Random value used during encryption.
  - `ciphertext (bytes)`: Encrypted text to decrypt.

- **Returns:**
  - `plaintext (bytes)`: The decrypted original message.

### `generate_aes_key()`

Generates a random 128-bit AES key.

- **Returns:**
  - `key (bytes)`: Randomly generated 128-bit key (16 bytes).

### `sign_input_text(sender, addr, function_selector, ct, key)`

Signs an input message composed of multiple parts, including sender address, contract address, function selector, and ciphertext.

- **Parameters:**
  - `sender (bytes)`: Sender address.
  - `addr (bytes)`: Contract address.
  - `function_selector (str)`: Ethereum function selector (in hex).
  - `ct (bytes)`: Ciphertext (concatenated).
  - `key (bytes)`: Private key for signing.

- **Returns:**
  - `signature (bytes)`: Digital signature of the message.

### `sign(message, key)`

Signs a `message` using the provided `key` (Ethereum-style private key).

- **Parameters:**
  - `message (bytes)`: Message to sign.
  - `key (bytes)`: Private key to use for signing.

- **Returns:**
  - `signature (bytes)`: The generated signature.

### `build_input_text(plaintext, user_aes_key, sender, contract, function_selector, signing_key)`

Encrypts a plaintext integer and signs the resulting ciphertext along with other parameters.

- **Parameters:**
  - `plaintext (int)`: Integer to encrypt.
  - `user_aes_key (bytes)`: AES key for encryption.
  - `sender (object)`: Ethereum-like sender object (with `address` attribute).
  - `contract (object)`: Ethereum-like contract object (with `address` attribute).
  - `function_selector (str)`: Function selector (in hex).
  - `signing_key (bytes)`: Signing key for signature.

- **Returns:**
  - `dict`: Contains the `ciphertext` and `signature`.

### `build_string_input_text(plaintext, user_aes_key, sender, contract, function_selector, signing_key)`

Encrypts and signs string-based input data, breaking it into 8-byte chunks.

- **Parameters:**
  - `plaintext (str)`: String to encrypt.
  - `user_aes_key (bytes)`: AES key for encryption.
  - `sender (object)`: Ethereum-like sender object.
  - `contract (object)`: Ethereum-like contract object.
  - `function_selector (str)`: Function selector (in hex).
  - `signing_key (bytes)`: Signing key for signature.

- **Returns:**
  - `dict`: Contains the `ciphertext` and `signature`.

### `decrypt_uint(ciphertext, user_key)`

Decrypts a ciphertext into an unsigned integer using AES.

- **Parameters:**
  - `ciphertext (int)`: Ciphertext to decrypt (in integer format).
  - `user_key (bytes)`: AES key to use for decryption.

- **Returns:**
  - `int`: The decrypted integer.

### `decrypt_string(ciphertext, user_key)`

Decrypts a ciphertext back into a string, handling multiple formats of ciphertext.

- **Parameters:**
  - `ciphertext (dict/tuple)`: Ciphertext to decrypt, can be in event or state variable format.
  - `user_key (bytes)`: AES key to use for decryption.

- **Returns:**
  - `str`: The decrypted string.

### `generate_rsa_keypair()`

Generates an RSA key pair for encryption and decryption.

- **Returns:**
  - `private_key_bytes (bytes)`: Serialized private key.
  - `public_key_bytes (bytes)`: Serialized public key.

### `decrypt_rsa(private_key_bytes, ciphertext)`

Decrypts a ciphertext using RSA and a provided private key.

- **Parameters:**
  - `private_key_bytes (bytes)`: Private key used for decryption.
  - `ciphertext (bytes)`: Ciphertext to decrypt.

- **Returns:**
  - `plaintext (bytes)`: Decrypted plaintext.
  

# Web3 Utilities (utils.py)
## Functions

### `web3_connected(web3)`

Checks if the Web3 instance is connected to the blockchain node.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.

- **Returns:**
  - `bool`: `True` if connected, otherwise `False`.

### `print_network_details(web3)`

Prints details about the connected network, such as the provider, chain ID, and the latest block hash.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.

### `print_account_details(web3)`

Prints details about the default account, including its address, balance in Wei and Ether, and the account nonce.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.

### `init_web3(node_https_address, eoa, error_not_connected=True)`

Initializes the Web3 instance and sets up the default account. It also injects the Geth POA middleware for POA chains.

- **Parameters:**
  - `node_https_address (str)`: The Ethereum node's HTTPS address.
  - `eoa (eth_account.Account)`: The account to set as the default.
  - `error_not_connected (bool)`: If `True`, raises an error if the connection fails.

- **Returns:**
  - `web3 (Web3)`: Initialized Web3 instance.

### `get_eoa(account_private_key)`

Creates an externally owned account (EOA) from a private key.

- **Parameters:**
  - `account_private_key (str)`: The private key for the account.

- **Returns:**
  - `eoa (eth_account.Account)`: The Ethereum account object.

### `validate_address(address)`

Validates if the given address is a valid Ethereum address and returns the checksum version of the address.

- **Parameters:**
  - `address (str)`: The Ethereum address.

- **Returns:**
  - `dict`: Contains `valid` (boolean) and `safe` (checksum address).

### `get_latest_block(web3)`

Retrieves the latest block on the blockchain.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.

- **Returns:**
  - `block (dict)`: The latest block.

### `get_nonce(web3)`

Retrieves the nonce (transaction count) for the default account.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.

- **Returns:**
  - `int`: The transaction count (nonce).

### `get_native_balance(web3, address=None)`

Gets the native token balance (e.g., Ether) for a given address or the default account.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.
  - `address (str, optional)`: The Ethereum address. Defaults to the default account.

- **Returns:**
  - `int`: The balance in Wei.

### `load_contract(file_path)`

Loads a Solidity contract source code from a file.

- **Parameters:**
  - `file_path (str)`: Path to the Solidity contract file.

- **Returns:**
  - `str`: The contract source code.

### `transfer_native(web3, recipient_address, private_key, amount_to_transfer_ether, native_gas_units)`

Transfers the native token (e.g., Ether) from the default account to a recipient address.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.
  - `recipient_address (str)`: Address to send the Ether.
  - `private_key (str)`: Private key of the sender.
  - `amount_to_transfer_ether (float)`: Amount of Ether to transfer.
  - `native_gas_units (int)`: Gas units to use for the transaction.

- **Returns:**
  - `dict`: Transaction receipt.

### `deploy_contract(contract, kwargs, tx_params)`

Deploys a smart contract with the given constructor arguments and transaction parameters.

- **Parameters:**
  - `contract (Contract)`: Web3 contract instance.
  - `kwargs (dict)`: Constructor arguments for the contract.
  - `tx_params (dict)`: Transaction parameters including gas limit, gas price, and private key.

- **Returns:**
  - `dict`: Transaction receipt.

### `exec_func_via_transaction(func, tx_params)`

Executes a contract function via a transaction.

- **Parameters:**
  - `func (ContractFunction)`: Contract function to execute.
  - `tx_params (dict)`: Transaction parameters including gas limit, gas price, and private key.

- **Returns:**
  - `dict`: Transaction receipt.

### `sign_and_send_tx(web3, private_key, transaction)`

Signs a transaction with the provided private key and sends it to the blockchain.

- **Parameters:**
  - `web3 (Web3)`: Web3 instance.
  - `private_key (str)`: Private key to sign the transaction.
  - `transaction (dict)`: Transaction details.

- **Returns:**
  - `dict`: Transaction receipt.

#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-python/issues)
