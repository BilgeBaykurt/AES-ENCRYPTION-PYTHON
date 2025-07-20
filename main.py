from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

# Generate a secure 256-bit AES key
def generate_key():
    key = os.urandom(32)  # 256-bit = 32 bytes
    with open("aes.key", "wb") as key_file:
        key_file.write(key)
    return key

# Load key from file
def load_key():
    with open("aes.key", "rb") as key_file:
        return key_file.read()

# AES-GCM encryption
def encrypt_file(file_path, key):
    if not file_path.endswith(".txt"):
        raise ValueError("Only .txt files are supported.")

    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Generate 96-bit IV
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + ".enc", "wb") as f:
        f.write(iv + encryptor.tag + ciphertext)

    print("[+] File encrypted using AES-256-GCM.")

# Usage
if __name__ == "__main__":
    file_path = input("Enter .txt file path: ")
    if not os.path.exists("aes.key"):
        key = generate_key()
    else:
        key = load_key()

    encrypt_file(file_path, key)
