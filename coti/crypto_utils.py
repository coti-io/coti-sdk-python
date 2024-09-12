import binascii
from array import array

from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from eth_keys import keys

block_size = AES.block_size
address_size = 20
func_sig_size = 4
ct_size = 32
key_size = 32


def encrypt(key, plaintext):
    # Ensure plaintext is smaller than 128 bits (16 bytes)
    if len(plaintext) > block_size:
        raise ValueError("Plaintext size must be 128 bits or smaller.")

    # Ensure key size is 128 bits (16 bytes)
    if len(key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Generate a random value 'r' of the same length as the block size
    r = get_random_bytes(block_size)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # Pad the plaintext with zeros if it's smaller than the block size
    plaintext_padded = bytes(block_size - len(plaintext)) + plaintext

    # XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    ciphertext = bytes(x ^ y for x, y in zip(encrypted_r, plaintext_padded))

    return ciphertext, r


def decrypt(key, r, ciphertext):
    if len(ciphertext) != block_size:
        raise ValueError("Ciphertext size must be 128 bits.")

    # Ensure key size is 128 bits (16 bytes)
    if len(key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Ensure random size is 128 bits (16 bytes)
    if len(r) != block_size:
        raise ValueError("Random size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    plaintext = bytes(x ^ y for x, y in zip(encrypted_r, ciphertext))

    return plaintext


def generate_aes_key():
    # Generate a random 128-bit AES key
    key = get_random_bytes(block_size)

    return key


def sign_input_text(sender, addr, func_sig, ct, key):
    # Ensure all input sizes are the correct length
    if len(sender) != address_size:
        raise ValueError(f"Invalid sender address length: {len(sender)} bytes, must be {address_size} bytes")
    if len(addr) != address_size:
        raise ValueError(f"Invalid contract address length: {len(addr)} bytes, must be {address_size} bytes")
    if len(func_sig) != func_sig_size:
        raise ValueError(f"Invalid signature size: {len(func_sig)} bytes, must be {func_sig_size} bytes")
    if len(ct) != ct_size:
        raise ValueError(f"Invalid ct length: {len(ct)} bytes, must be {ct_size} bytes")
    # Ensure the key is the correct length
    if len(key) != key_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {key_size} bytes")

    # Create the message to be signed by appending all inputs
    message = sender + addr + func_sig + ct

    return sign(message, key)


def sign(message, key):
    # Sign the message
    pk = keys.PrivateKey(key)
    signature = pk.sign_msg(message).to_bytes()

    return signature


def build_input_text(plaintext, user_aes_key, sender, contract, func_sig, signing_key):
    sender_address_bytes = bytes.fromhex(sender.address[2:])
    contract_address_bytes = bytes.fromhex(contract.address[2:])

    # Convert the integer to a byte slice with size aligned to 8.
    plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')

    # Encrypt the plaintext with the user's AES key
    ciphertext, r = encrypt(user_aes_key, plaintext_bytes)
    ct = ciphertext + r

    # Create the function signature
    func_hash = get_func_sig(func_sig)
    # Sign the message
    signature = sign_input_text(sender_address_bytes, contract_address_bytes, func_hash, ct, signing_key)

    # Convert the ct to an integer
    int_cipher_text = int.from_bytes(ct, byteorder='big')

    return int_cipher_text, signature


def build_string_input_text(plaintext, user_aes_key, sender, contract, func_sig, signing_key):
    encoded_plaintext = array('B', plaintext.encode('utf-8'))
    encrypted_str = [{'ciphertext': 0, 'signature': b''} for _ in range(len(encoded_plaintext))]
    for i in range(len(encoded_plaintext)):
        ct_int, signature = build_input_text(int(encoded_plaintext[i]), user_aes_key, sender, contract,
                                             func_sig, signing_key)
        encrypted_str[i] = {'ciphertext': ct_int, 'signature': signature}

    return encrypted_str


def decrypt_uint(ciphertext, user_key):
    # Convert ct to bytes (big-endian)
    byte_array = ciphertext.to_bytes(32, byteorder='big')

    # Split ct into two 128-bit arrays r and cipher
    cipher = byte_array[:block_size]
    r = byte_array[block_size:]

    # Decrypt the cipher
    decrypted_message = decrypt(user_key, r, cipher)

    # Print the decrypted cipher
    decrypted_uint = int.from_bytes(decrypted_message, 'big')

    return decrypted_uint


def decrypt_string(ciphertext, user_key):
    string_from_input_tx = ""
    for input_text_from_tx in ciphertext:
        decrypted_input_from_tx = decrypt_uint(input_text_from_tx, user_key)
        byte_length = (decrypted_input_from_tx.bit_length() + 7) // 8  # calculate the byte length

        # Convert the integer to bytes
        decrypted_bytes = decrypted_input_from_tx.to_bytes(byte_length, byteorder='big')

        # Decode the bytes to a string
        string_from_input_tx += decrypted_bytes.decode('utf-8')

    return string_from_input_tx


def generate_rsa_keypair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Get public key
    public_key = private_key.public_key()
    # Serialize public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes


def decrypt_rsa(private_key_bytes, ciphertext):
    # Load private key
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    # Decrypt ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

#This function recovers a user's key by decrypting two encrypted key shares with the given private key,
#and then XORing the two key shares together.
def recover_user_key(private_key_bytes, encrypted_key_share0, encrypted_key_share1):
    key_share0 = decrypt_rsa(private_key_bytes, encrypted_key_share0)
    key_share1 = decrypt_rsa(private_key_bytes, encrypted_key_share1)

    # XOR both key shares to get the user key
    return bytes([a ^ b for a, b in zip(key_share0, key_share1)])


# Function to compute Keccak-256 hash
def keccak256(data):
    # Create Keccak-256 hash object
    hash_obj = keccak.new(digest_bits=256)

    # Update hash object with data
    hash_obj.update(data)

    # Compute hash and return
    return hash_obj.digest()


def get_func_sig(function_signature):
    # Convert function signature to bytes
    function_signature_bytes = function_signature.encode('utf-8')

    # Compute Keccak-256 hash on the function signature
    function_signature_bytes_hash = keccak256(function_signature_bytes)

    # Take first 4 bytes of the hash
    return function_signature_bytes_hash[:4]
