import ctypes
import os
import requests
import secrets
import math
import base64
import ast
from hashlib import sha256
from ctypes import CDLL

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AES_DLL_PATH = os.path.join(SCRIPT_DIR, 'aeslib.dll')

############
#Diffie Hellman
############
# get the parameters needed foe diffie hellman
def get_diffie_hellman_parameters() -> tuple[int, int]:
    url = "https://2ton.com.au/getprimes/random/3072"

    # Send a GET request
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code != 200:
        # Print an error message if the request was not successful
        print(f"Error: {response.status_code}")

    data = response.json()

    p = int(data["p"]["base10"])
    g = int(data["g"]["base10"])

    return p, g


# generate the private key for diffie hellman
def generate_private_key(p: int) -> int:
    return secrets.randbelow(p - 1) + 2


# calculate the public key to send to the other end according to the private key
def calc_public_key(private_key: int, p: int, g: int) -> int:
    return pow(g, private_key, p)


# calculate the key that was created in the sharing process
def calc_shared_key(private_key: int, public_key: int, p: int) -> int:
    return pow(public_key, private_key, p)


# convert the key from large number to 16 bytes string
def int_to_key(num: int) -> bytes:
    bytes_key = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')

    if len(bytes_key) < 16:
        bytes_key = bytes_key.rjust(16, b'\x00')
    elif len(bytes_key) > 16:
        bytes_key = sha256(bytes_key).digest()[:16]

    return bytes_key


# calculate the key and make it as bytes
def get_aes_key(recived_key: int, P: int, private_key: int) -> bytes:   
    shared_key = calc_shared_key(private_key, recived_key, P)

    aes_key = int_to_key(shared_key)

    return aes_key

############
#   AES
############
# use the aes encryption form the dll
def aes_encrypt(text: bytes, key: bytes) -> str:
    aes_dll = CDLL(AES_DLL_PATH)
    length = len(text)

    aes_dll.AES_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    aes_dll.AES_encrypt.restype = ctypes.POINTER(ctypes.c_char)
    cipher_pointer = aes_dll.AES_encrypt(text, key, length)

    cipher_length = math.ceil(length / 16) * 16

    # Adjust the length based on your actual data size
    encrypted_data = ctypes.string_at(cipher_pointer, cipher_length)
    encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
    return encrypted_data_b64


# use the aes decryption form the dll
# get cipher as base64
# return text as str
def aes_decrypt(cipher_b64: bytes, key: bytes) -> bytes:
    aes_dll = CDLL(AES_DLL_PATH)
    cipher = base64.b64decode(cipher_b64)
    length = len(cipher)

    aes_dll.AES_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    aes_dll.AES_decrypt.restype = ctypes.POINTER(ctypes.c_char)
    data_pointer = aes_dll.AES_decrypt(cipher, key, length)

    decrypted_data = ctypes.string_at(data_pointer, length)
    decrypted_data = remove_pad(decrypted_data)
    return decrypted_data

# remove the padding used while encrypting
def remove_pad(text: bytes) -> bytes:
    if len(text) <= 0:
        return b'' 
    last_byte = text[-1]
    for i in range(1, last_byte):
        if text[-i] != last_byte:
            return text
    return text[:-last_byte]

############
#RSA
############
def b64_key_to_tuple(key_b64: str) -> tuple[int, int]:
    key_str = base64.b64decode(key_b64).decode('utf-8')
    key = ast.literal_eval(key_str)
    return key

def get_rsa_parameters() -> tuple[int, int]:
    url = "https://2ton.com.au/getprimes/random/2048"

    # Send a GET request
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code != 200:
        # Print an error message if the request was not successful
        print(f"Error: {response.status_code}")

    data = response.json()

    p = int(data["p"]["base10"])
    q = int(data["q"]["base10"])

    return p, q


def mod_inverse(a: int, m: int) -> int:
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

"""
generate RSA key pair,
save them as tuple (n, d) in b64 
"""
def rsa_generate_key_pair() -> tuple[str, str]:
    p, q = get_rsa_parameters()

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    d = mod_inverse(e, phi_n)

    public_key = base64.b64encode(str((n, e)).encode('utf-8')).decode('utf-8')
    private_key = base64.b64encode(str((n, d)).encode('utf-8')).decode('utf-8')

    return public_key, private_key


def rsa_encrypt(message: int, public_key: str) -> int:
    n, e = b64_key_to_tuple(public_key)
    return pow(message, e, n)


def rsa_decrypt(ciphertext: int, private_key: str) -> int:
    n, d = b64_key_to_tuple(private_key)
    return pow(ciphertext, d, n)

"""
sign messege with key for verification
messege (str): string to encrypt
private_key (b64 as str)
"""
def rsa_sign(message: str, private_key: str) -> int:
    hashed_message = sha256(message.encode()).digest()
    signature = rsa_encrypt(int.from_bytes(hashed_message, 'big'), private_key)
    return signature

"""
verify messege was signed with the correct key
messege (str): string to encrypt
signature (int): signature recived
public_key (b64 as str): key
"""
def rsa_verify(message: str, signature: int, public_key: str) -> bool:
    hashed_message = sha256(message.encode()).digest()
    decrypted_signature = rsa_decrypt(signature, public_key)
    return int.from_bytes(hashed_message, 'big') == decrypted_signature
