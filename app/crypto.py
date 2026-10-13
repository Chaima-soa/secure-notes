import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_aes_key():
    key_hex = os.environ.get("AES_KEY")

    if not key_hex:
        raise RuntimeError("AES_KEY is not configured.")

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise RuntimeError("AES_KEY must be a valid hexadecimal value.") from exc

    if len(key) != 32:
        raise RuntimeError("AES_KEY must be exactly 32 bytes.")

    return key


def encrypt_note(plaintext):
    key = get_aes_key()

    aesgcm = AESGCM(key)

    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None,
    )

    encrypted_data = nonce + ciphertext

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt_note(encrypted_data):
    key = get_aes_key()

    raw_data = base64.b64decode(encrypted_data)

    nonce = raw_data[:12]
    ciphertext = raw_data[12:]

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None,
    )

    return plaintext.decode("utf-8")
