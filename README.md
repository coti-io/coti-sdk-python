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

### Crypto Utilities (crypto_utils.py) Functions

### 1. `encrypt(key, plaintext)`

**Purpose:** Encrypts a plaintext message using AES encryption with a provided key.

**Usage:**
```python
ciphertext, r = encrypt(key, plaintext)
```

**Parameters:**
- `key`: A 128-bit (16-byte) AES key.
- `plaintext`: The plaintext message to be encrypted. Must be 128 bits (16 bytes) or smaller.

**Returns:**
- `ciphertext`: The encrypted message.
- `r`: The random value used during encryption.

### 2. `decrypt(key, r, ciphertext)`

**Purpose:** Decrypts a ciphertext message using AES decryption with a provided key and random value.

**Usage:**
```python
plaintext = decrypt(key, r, ciphertext)
```

**Parameters:**
- `key`: A 128-bit (16-byte) AES key.
- `r`: The random value used during encryption.
- `ciphertext`: The encrypted message to be decrypted.

**Returns:**
- `plaintext`: The decrypted message.

### 3. `load_aes_key(file_path)`

**Purpose:** Loads a 128-bit AES key from a file.

**Usage:**
```python
key = load_aes_key(file_path)
```

**Parameters:**
- `file_path`: Path to the file containing the hex-encoded AES key.

**Returns:**
- `key`: The 128-bit AES key.

### 4. `write_aes_key(file_path, key)`

**Purpose:** Writes a 128-bit AES key to a file in hex-encoded format.

**Usage:**
```python
write_aes_key(file_path, key)
```

**Parameters:**
- `file_path`: Path to the file where the key will be written.
- `key`: The 128-bit AES key.

### 5. `generate_aes_key()`

**Purpose:** Generates a random 128-bit AES key.

**Usage:**
```python
key = generate_aes_key()
```

**Returns:**
- `key`: The generated 128-bit AES key.

### 6. `generate_ECDSA_private_key()`

**Purpose:** Generates a new ECDSA private key.

**Usage:**
```python
private_key = generate_ECDSA_private_key()
```

**Returns:**
- `private_key`: The raw bytes of the ECDSA private key.

### 7. `signIT(sender, addr, func_sig, ct, key)`

**Purpose:** Signs a message composed of various inputs using a private key.

**Usage:**
```python
signature = signIT(sender, addr, func_sig, ct, key)
```

**Parameters:**
- `sender`: The sender's address.
- `addr`: The contract address.
- `func_sig`: The function signature.
- `ct`: The ciphertext.
- `key`: The private key used for signing.

**Returns:**
- `signature`: The generated signature.

### 8. `sign(message, key)`

**Purpose:** Signs a message using a private key.

**Usage:**
```python
signature = sign(message, key)
```

**Parameters:**
- `message`: The message to be signed.
- `key`: The private key used for signing.

**Returns:**
- `signature`: The generated signature.

### 9. `build_input_text(plaintext, user_aes_key, sender, contract, func_sig, signing_key)`

**Purpose:** Builds input text by encrypting the plaintext and signing it.

**Usage:**
```python
int_cipher_text, signature = build_input_text(plaintext, user_aes_key, sender, contract, func_sig, signing_key)
```

**Parameters:**
- `plaintext`: The plaintext message.
- `user_aes_key`: The user's AES key.
- `sender`: The sender's address.
- `contract`: The contract address.
- `func_sig`: The function signature.
- `signing_key`: The private key used for signing.

**Returns:**
- `int_cipher_text`: The integer representation of the ciphertext.
- `signature`: The generated signature.

### 10. `generate_rsa_keypair()`

**Purpose:** Generates an RSA key pair.

**Usage:**
```python
private_key_bytes, public_key_bytes = generate_rsa_keypair()
```

**Returns:**
- `private_key_bytes`: The serialized private key.
- `public_key_bytes`: The serialized public key.

### 11. `encrypt_rsa(public_key_bytes, plaintext)`

**Purpose:** Encrypts plaintext using RSA encryption with a provided public key.

**Usage:**
```python
ciphertext = encrypt_rsa(public_key_bytes, plaintext)
```

**Parameters:**
- `public_key_bytes`: The serialized public key.
- `plaintext`: The plaintext message to be encrypted.

**Returns:**
- `ciphertext`: The encrypted message.

### 12. `decrypt_rsa(private_key_bytes, ciphertext)`

**Purpose:** Decrypts ciphertext using RSA decryption with a provided private key.

**Usage:**
```python
plaintext = decrypt_rsa(private_key_bytes, ciphertext)
```

**Parameters:**
- `private_key_bytes`: The serialized private key.
- `ciphertext`: The encrypted message to be decrypted.

**Returns:**
- `plaintext`: The decrypted message.

### 13. `keccak256(data)`

**Purpose:** Computes the Keccak-256 hash of the provided data.

**Usage:**
```python
hash_value = keccak256(data)
```

**Parameters:**
- `data`: The data to be hashed.

**Returns:**
- `hash_value`: The computed hash.

### 14. `get_func_sig(function_signature)`

**Purpose:** Computes the function signature hash using Keccak-256.

**Usage:**
```python
func_sig_hash = get_func_sig(function_signature)
```

**Parameters:**
- `function_signature`: The function signature string.

**Returns:**
- `func_sig_hash`: The first 4 bytes of the computed hash.

### Utilities (utils.py) Functions

### 1. `web3_connected(web3)`

**Purpose:** Checks if the Web3 instance is connected.

**Usage:**
```python
connected = web3_connected(web3)
```

**Parameters:**
- `web3`: An instance of Web3.

**Returns:**
- `connected`: Boolean indicating if Web3 is connected.

### 2. `print_network_details(web3)`

**Purpose:** Prints the network details of the Web3 instance.

**Usage:**
```python
print_network_details(web3)
```

**Parameters:**
- `web3`: An instance of Web3.

### 3. `print_account_details(web3)`

**Purpose:** Prints the account details of the default account in the Web3 instance.

**Usage:**
```python
print_account_details(web3)
```

**Parameters:**
- `web3`: An instance of Web3.

### 4. `init_web3(node_https_address, eoa, error_not_connected=True)`

**Purpose:** Initializes the Web3 instance with the given node address and externally owned account (EOA).

**Usage:**
```python
web3 = init_web3(node_https_address, eoa)
```

**Parameters:**
- `node_https_address`: The HTTPS address of the COTI node.
- `eoa`: The externally owned account.
- `error_not_connected`: Boolean indicating whether to raise an error if not connected.

**Returns:**
- `web3`: The initialized Web3 instance.

### 5. `get_eoa(account_private_key)`

**Purpose:** Generates an externally owned account (EOA) from a private key.

**Usage:**
```python
eoa = get_eoa(account_private_key)
```

**Parameters:**
- `account_private_key`: The private key of the account.

**Returns:**
- `eoa`: The generated EOA.

### 6. `validate_address(address)`

**Purpose:** Validates and returns the checksum address for a given address.

**Usage:**
```python
result = validate_address(address)
```

**Parameters:**
- `address`: The address to be validated.

**Returns:**
- `result`: A dictionary with `valid` (boolean) and `safe` (checksum address).

### 7. `get_latest_block(web3)`

**Purpose:** Retrieves the latest block from the COTI network.

**Usage:**
```python
latest_block = get_latest_block(web3)
```

**Parameters:**
- `web3`: An instance of Web3.

**Returns:**
- `latest_block`: The latest block object.

### 8. `get_nonce(web3)`

**Purpose:** Retrieves the nonce for the default account.

**Usage:**
```python
nonce = get_nonce(web3)
```

**Parameters:**
- `web3`: An instance of Web3.

**Returns:**
- `nonce`: The nonce for the default account.

### 9. `get_address_valid_and_checksum(address)`

**Purpose:** Validates an address and returns the checksum address.

**Usage:**
```python
result = get_address_valid_and_checksum(address)
```

**Parameters:**
- `address`: The address to be validated.

**Returns:**
- `result`: A dictionary with `valid` (boolean) and `safe` (checksum address).

### 10. `address_valid(address)`

**Purpose:** Checks if an address is valid.

**Usage:**
```python
valid = address_valid(address)
```

**Parameters:**
- `address`: The address to be validated.

**Returns:**
- `valid`: Boolean indicating if the address is valid.

### 11. `get_native_balance(web3, address=None)`

**Purpose:** Retrieves the native balance of an address.

**Usage:**
```python
balance = get_native_balance(web3, address)
```

**Parameters:**
- `web3`: An instance of Web3.
- `address`: The address to check the balance of (default is the default account).

**Returns:**
- `balance`: The native balance in wei.

### 12. `load_contract(file_path)`

**Purpose:** Loads a Solidity contract source code from a file.

**Usage:**
```python
contract_code = load_contract(file_path)
```

**Parameters:**
- `file_path`: Path to the Solidity source code file.

**Returns:**
- `contract_code`: The content of the file.

### 13. `transfer_native(web3, recipient_address, private_key, amount_to_transfer_ether, native_gas_units)`

**Purpose:** Transfers native cryptocurrency from the default account to a recipient address.

**Usage:**
```python
tx_receipt = transfer_native(web3, recipient_address, private_key, amount_to_transfer_ether, native_gas_units)
```

**Parameters:**
- `web3`: An instance of Web3.
- `recipient_address`: The address of the recipient.
- `private_key`: The private key of the sender.
- `amount_to_transfer_ether`: The amount of Ether to transfer.
- `native_gas_units`: The gas limit for the transaction.

**Returns:**
- `tx_receipt`: The transaction receipt.

### 14. `validate_gas_estimation(web3, tx)`

**Purpose:** Validates the gas estimation for a transaction.

**Usage:**
```python
validate_gas_estimation(web3, tx)
```

**Parameters:**
- `web3`: An instance of Web3.
- `tx`: The transaction object.

### 15. `is_gas_units_estimation_valid(web3, tx)`

**Purpose:** Checks if the provided gas units are sufficient for the transaction.

**Usage:**
```python
valid, gas_estimate = is_gas_units_estimation_valid(web3, tx)
```

**Parameters:**
- `web3`: An instance of Web3.
- `tx`: The transaction object.

**Returns:**
- `valid`: Boolean indicating if the gas units are sufficient.
- `gas_estimate`: The estimated gas units.

### 16. `get_function_signature(function_abi)`

**Purpose:** Generates the function signature from the ABI.

**Usage:**
```python
func_sig = get_function_signature(function_abi)
```

**Parameters:**
- `function_abi`: The ABI of the function.

**Returns:**
- `func_sig`: The function signature.

### 17. `deploy_contract(contract, kwargs, tx_params)`

**Purpose:** Deploys a contract with the given parameters.

**Usage:**
```python
tx_receipt = deploy_contract(contract, kwargs, tx_params)
```

**Parameters:**
- `contract`: The contract object.
- `kwargs`: Keyword arguments for the contract constructor.
- `tx_params`: Transaction parameters.

**Returns:**
- `tx_receipt`: The transaction receipt.

### 18. `exec_func_via_transaction(func, tx_params)`

**Purpose:** Executes a contract function via a transaction.

**Usage:**
```python
tx_receipt = exec_func_via_transaction(func, tx_params)
```

**Parameters:**
- `func`: The contract function to be executed.
- `tx_params`: Transaction parameters.

**Returns:**
- `tx_receipt`: The transaction receipt.

### 19. `sign_and_send_tx(web3, private_key, transaction)`

**Purpose:** Signs and sends a transaction.

**Usage:**
```python
tx_receipt = sign_and_send_tx(web3, private_key, transaction)
```

**Parameters:**
- `web3`: An instance of Web3.
- `private_key`: The private key of the sender.
- `transaction`: The transaction object.

**Returns:**
- `tx_receipt`: The transaction receipt.

### 20. `decrypt_value(contract_value, user_key)`

**Purpose:** Decrypts a value stored in a contract using a user key.

**Usage:**
```python
decrypted_balance = decrypt_value(contract_value, user_key)
```

**Parameters:**
- `contract_value`: The value to be decrypted.
- `user_key`: The user's AES key.

**Returns:**
- `decrypted_balance`: The decrypted value.


## Pending enhancements
* Versioned pypi library
* Extending examples such as confidential ERC20 minting, confidential NFT (deployment and actions) and more.

#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-python/issues)

