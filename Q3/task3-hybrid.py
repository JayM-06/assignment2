"""
Q3: Hybrid encryption (AES + RSA) to securely send task2.txt

LECTORIAL CODE REFERENCES
Lectorial 8 - hybrid_crypto.py
    This example does hybrid encryption on a string, we used it as the base 
    for our code. What we used from it:
      - the structure and function names: generate_rsa_keys(),
        encrypt_message() and decrypt_message()
      - rsa.generate_private_key() with public_exponent=65537 and
        key_size=2048 to create the RSA key pair
      - os.urandom(32) for random AES-256 key and os.urandom(16) for the IV
      - Cipher(algorithms.AES(key), modes.CFB(iv)) with the encryptor and
        decryptor to encrypt and decrypt the data
      - encrypting the AES key with the public key using RSA OAEP padding
        (MGF1 with SHA256), decrypting it with the private key
      - b64encode to print the keys and encrypted values to the user
    What we changed:
      - it now encrypts and decrypts a file (task2.txt) instead of a string
      - the RSA keys are saved to separate .pem files and loaded back from
        them, and the decrypted data is saved to its own file
      - the encrypted file and the encrypted AES key are saved to files
      - all file paths use the BASE variable
      - the RSA public and private keys and the AES key are also displayed
      - the program prompts the user to type the message, which is saved
        to input/task2.txt and then encrypted as a file

Lectorial 5 - aes_cfb_file.py
    What we used from it:
      - it showed that AES in CFB mode needs no padding
      - reading and writing files as bytes ("rb" and "wb")
      - storing the IV at the start of the encrypted file and reading the
        first 16 bytes back as the IV when decrypting
      - the BASE = os.path.dirname(os.path.abspath(__file__)) line

Lectorial 5 - rsa_padding_file.py
    Used as a second reference for the RSA OAEP padding block and for
    reading and writing the files with BASE.

So AES encrypts the file and RSA encrypts the AES key.
1. the code generates the RSA keys saved in the keys folder
2. we encrypt the file with a random AES key, then encrypt that AES
    key with the RSA public key
3. decrypts the AES key with their RSA private key, then decrypts the file with the AES key
"""

# uses cryptography library
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode
import os

# Making sure the file path is able to work on all os
BASE = os.path.dirname(os.path.abspath(__file__))

# Folder paths built from BASE so they work on any operating system
input_file = os.path.join(BASE, "input", "task2.txt")
keys_dir = os.path.join(BASE, "keys")
output_dir = os.path.join(BASE, "output")
public_key_file = os.path.join(keys_dir, "public.hybrid.pem")
private_key_file = os.path.join(keys_dir, "private.hybrid.pem")
encrypted_file = os.path.join(output_dir, "task2_enc")
encrypted_key_file = os.path.join(output_dir, "task2_aes_key_enc")
decrypted_file = os.path.join(output_dir, "task2_dec.txt")

# make sure the folders exist before saving files
os.makedirs(keys_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

# ask the user for the message and save it to the input file
def get_message():
    # make sure the input folder exists before saving the file
    os.makedirs(os.path.dirname(input_file), exist_ok=True)

    # keep asking until the user types something
    while True:
        text = input("Enter an appropriate message to encrypt: ").strip()
        if text == "":
            print("Error: The message cannot be empty.")
        else:
            break

    # save the message so the rest of the program can read it as a file
    with open(input_file, "w", encoding="utf-8") as f:
        f.write(text)
    print("Message saved to the input folder as task2.txt")

# Generating RSA keys where each key is saved in its own file
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # turn the keys into pem text so they can be saved and displayed
    # using pem file rather than normal txt as that is used for RSA
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # save each key in its own file
    with open(private_key_file, "wb") as private_file:
        private_file.write(private_pem)
    with open(public_key_file, "wb") as public_file:
        public_file.write(public_pem)

    return private_pem, public_pem


# encrypt the file with AES, then encrypt the AES key with RSA
def encrypt_message():
    # read the file to be sent
    with open(input_file, "rb") as in_file:
        message = in_file.read()

    # Generate a random symmetric key for AES 32 bytes = AES-256
    symmetric_key = os.urandom(32)

    # Encrypt the data with AES CFB mode
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()

    # get the public key from its file
    with open(public_key_file, "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())

    # encrypt the symmetric key with RSA with OAEP padding
    encrypted_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # save the encrypted file with IV first then data and the encrypted AES key
    with open(encrypted_file, "wb") as enc_file:
        enc_file.write(iv + encrypted_message)
    with open(encrypted_key_file, "wb") as enc_key_file:
        enc_key_file.write(encrypted_key)

    return message, symmetric_key, iv, encrypted_message, encrypted_key


# decrypts the AES key with RSA, then decrypts the file with AES
def decrypt_message():
    # read the encrypted file, the first 16 bytes are the IV
    with open(encrypted_file, "rb") as enc_file:
        iv = enc_file.read(16)
        encrypted_message = enc_file.read()
    with open(encrypted_key_file, "rb") as enc_key_file:
        encrypted_key = enc_key_file.read()

    # load the private key from its file
    with open(private_key_file, "rb") as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None)

    # Decrypt the symmetric key
    symmetric_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the data
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # save the decrypted file in its own file
    with open(decrypted_file, "wb") as dec_file:
        dec_file.write(decrypted_message)

    return symmetric_key, decrypted_message


if __name__ == "__main__":
    get_message()

    # Generate RSA keys
    private_pem, public_pem = generate_rsa_keys()
    print("RSA public key:")
    print(public_pem.decode())
    print("RSA private key:")
    print(private_pem.decode())

    # Encrypt the file
    message, symmetric_key, iv, encrypted_message, encrypted_key = encrypt_message()
    print("Original:", message.decode())
    print("AES key:", b64encode(symmetric_key).decode())
    print("IV (Initialization Vector):", b64encode(iv).decode())
    print("Encrypted Message:", b64encode(encrypted_message).decode())
    print("Encrypted Symmetric Key:", b64encode(encrypted_key).decode())

    # Decrypt the file
    recovered_key, decrypted_message = decrypt_message()
    print("Recovered AES key:", b64encode(recovered_key).decode())
    print("Decrypted:", decrypted_message.decode())
    print("Decrypted file saved in the output folder")