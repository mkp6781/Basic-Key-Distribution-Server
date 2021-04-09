import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import socket


def send_message(data: dict, s: socket):
    json_format_data = json.dumps(data).encode('utf-8')
    s.sendall(json_format_data)


# encrypt plain_text using MD5 hash and store as user's secret key.
def md5_hash(plain_text: str) -> bytes:
    digest = hashes.Hash(hashes.MD5())
    digest.update(bytes(plain_text, encoding='utf-8'))
    hashed_pass = digest.finalize()
    base64_hashed_pass_bytes = base64.b64encode(hashed_pass)
    return base64_hashed_pass_bytes


def decrypt_msg(secret_key: bytes, msg_to_decrypt: str) -> dict:
    f = Fernet(secret_key)
    encrypted_msg_to_sender = json.dumps(msg_to_decrypt).encode('utf-8')
    decrypted_response = f.decrypt(encrypted_msg_to_sender)
    decrypted_response = json.loads(decrypted_response)
    return decrypted_response


def encrypt_msg(secret_key: bytes, msg_to_encrypt: dict) -> str:
    f = Fernet(secret_key)
    json_format_msg = json.dumps(msg_to_encrypt).encode('utf-8')
    encrypted_msg = f.encrypt(json_format_msg)
    encrypted_msg = encrypted_msg.decode("utf-8")
    return encrypted_msg


def derive_key(salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(b"hello world"))
    return key


def get_user_info(OUTPUT_FILE: str, pwdfile: str, name: str) -> tuple:
    # Get password hash of sender.
    with open(OUTPUT_FILE / pwdfile, "r") as pwd:
        lines = pwd.readlines()
        for line in lines:
            content = line.split(":")
            if content[1] == name:
                ip_addr_user = content[2]
                portno_user = content[3]
                salt_string = content[4]
    return (ip_addr_user, portno_user, salt_string)


def get_secret_key(salt_string: str) -> bytes:
    salt_bytes = salt_string.encode("utf-8")
    secret_key_sender = derive_key(salt_bytes)
    return secret_key_sender