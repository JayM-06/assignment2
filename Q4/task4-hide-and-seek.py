# uses cryptography library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os

# Making sure the file path is able to work on all os
BASE = os.path.dirname(os.path.abspath(__file__))

# Folder paths built from BASE so they work on any operating system
input_dir = os.path.join(BASE, "input")
keys_dir = os.path.join(BASE, "keys")
output_dir = os.path.join(BASE, "output")
image_file = os.path.join(input_dir, "image.jpeg")
message_file = os.path.join(input_dir, "task4_message.txt")
key_file = os.path.join(keys_dir, "task4_aes_key.bin")
stego_file = os.path.join(output_dir, "stego.jpeg")
decrypted_file = os.path.join(output_dir, "task4_decrypted.txt")

# make sure the folders exist before saving files
os.makedirs(input_dir, exist_ok=True)
os.makedirs(keys_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

# Label put at the start of our comment so we can find it again
marker = b"STEGO1:"

# The IV is 16 bytes and is stored in front of the encrypted message
iv_length = 16

# JPEG marker codes (every marker is 0xFF followed by a code byte)
start = 0xDA           # start of scan, the compressed pixel data begins here
comment = 0xFE           # comment segment, this is where we hide the data
max_seg_len = 65535  # the length field is 2 bytes so a segment can't be bigger


# encrypt the message with AES CFB mode
# a random key and a random IV are made every time we hide a message
def encrypt_message(message):
    # Generate a random symmetric key for AES 32 bytes = AES-256
    symmetric_key = os.urandom(32)

    # Encrypt the data with AES CFB mode using a random IV
    iv = os.urandom(iv_length)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode("utf-8")) + encryptor.finalize()

    # save the AES key in its own file, this is the stego-key
    # the person recovering the message needs same with stego image
    with open(key_file, "wb") as k_file:
        k_file.write(symmetric_key)

    return symmetric_key, iv, encrypted_message


# decrypt the message with the AES key from the key file
def decrypt_message(iv, encrypted_message):
    # load the AES key from its file
    with open(key_file, "rb") as k_file:
        symmetric_key = k_file.read()

    # Decrypt the data
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    return symmetric_key, decrypted_message


# list the segments of the JPEG
# a JPEG is a series of segments: 0xFF, a code byte, a 2 byte length, then data
# the length includes its own 2 bytes. We stop when the pixel data starts
# returns a list of (code, start, end) positions in the file
def list_segments(data):
    segments = []
    pos = 2  # skip the 2 byte start of image marker
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        code = data[pos + 1]
        if code == start:
            break
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        end = pos + 2 + length
        segments.append((code, pos, end))
        pos = end
    return segments


# check if a segment is a comment that holds the hidden message
def is_our_segment(data, code, start):
    # the data starts 4 bytes in: 0xFF, code, then 2 length bytes
    return code == comment and data[start + 4:start + 4 + len(marker)] == marker


# hide the encrypted message inside a JPEG comment segment
def hide(message):
    if not os.path.exists(image_file):
        print("Cannot find", image_file)
        print("Put a JPEG called image.jpeg in the input folder.")
        return

    with open(image_file, "rb") as image:
        data = image.read()

    # a JPEG always starts with FF D8
    if data[:2] != bytes([0xFF, 0xD8]):
        print("image.jpeg does not look like a valid JPEG.")
        return

    # if the image already has one of our messages then remove it first
    for code, start, end in reversed(list_segments(data)):
        if is_our_segment(data, code, start):
            data = data[:start] + data[end:]

    # save the plaintext message to the input folder
    with open(message_file, "w") as msg_file:
        msg_file.write(message)

    # encrypt the message with AES IV first, then the encrypted data
    symmetric_key, iv, encrypted_message = encrypt_message(message)
    payload = iv + encrypted_message

    # base64 keeps the bytes as plain text so they are safe in a comment
    body = marker + b64encode(payload)

    if len(body) + 2 > max_seg_len:
        print("Message is too long for a single comment segment.")
        return

    # build the comment segment: FF FE + length + marker + base64 text
    segment = bytes([0xFF, comment]) + (len(body) + 2).to_bytes(2, "big") + body

    # insert it after the APP segments at the start of the file
    insert_at = 2
    for code, start, end in list_segments(data):
        if 0xE0 <= code <= 0xEF:
            insert_at = end
        else:
            break

    with open(stego_file, "wb") as out_file:
        out_file.write(data[:insert_at] + segment + data[insert_at:])

    print("Original:", message)
    print("AES key:", b64encode(symmetric_key).decode())
    print("IV (Initialization Vector):", b64encode(iv).decode())
    print("Encrypted Message:", b64encode(encrypted_message).decode())
    print("Image size:", len(data), "bytes")
    print("Stego size:", len(data) + len(segment), "bytes")
    print("AES key saved in the keys folder")
    print("Stego image saved in the output folder")


# find the comment segment, then decrypt the message inside it
def reveal():
    if not os.path.exists(stego_file):
        print("Cannot find", stego_file)
        print("Run the hide option first.")
        return

    if not os.path.exists(key_file):
        print("Cannot find", key_file)
        print("The AES key file is needed to decrypt the message.")
        return

    with open(stego_file, "rb") as in_file:
        data = in_file.read()

    # look for our comment segment
    found = None
    for code, start, end in list_segments(data):
        if is_our_segment(data, code, start):
            found = data[start + 4 + len(marker):end]
            break

    if found is None:
        print("No hidden message found in this image.")
        return

    # turn the base64 text back into the payload bytes
    try:
        payload = b64decode(found, validate=True)
    except ValueError:
        print("Hidden data is corrupted.")
        return

    if len(payload) <= iv_length:
        print("Hidden data is incomplete.")
        return

    # the first 16 bytes are the IV, the rest is the encrypted message
    iv = payload[:iv_length]
    encrypted_message = payload[iv_length:]
    print("IV (Initialization Vector):", b64encode(iv).decode())
    print("Encrypted Message:", b64encode(encrypted_message).decode())

    recovered_key, decrypted_message = decrypt_message(iv, encrypted_message)
    print("Recovered AES key:", b64encode(recovered_key).decode())

    # CFB has no check for a wrong key, it gives garbage
    # so if the result is not readable text we assume the key was wrong
    try:
        text = decrypted_message.decode("utf-8")
    except UnicodeDecodeError:
        print("Decryption failed: wrong AES key or the data was modified.")
        return

    # save the decrypted message in its own file
    with open(decrypted_file, "w") as dec_file:
        dec_file.write(text)

    print("Decrypted:", text)
    print("Decrypted message saved in the output folder")


if __name__ == "__main__":
    while True:
        print("\n1) Hide message")
        print("2) Reveal message")
        print("3) Quit")
        choice = input("Selected: ").strip()

        if choice == "1":
            message = input("Enter the secret message: ").strip()
            # do not allow an empty message to be hidden
            if message == "":
                print("The message cannot be empty.")
            else:
                hide(message)
        elif choice == "2":
            reveal()
        elif choice == "3":
            break
        else:
            print("Please enter 1, 2 or 3.")