import base64
from cryptography.hazmat.primitives import hashes
import json
import socket

def send_message(data: dict, s: socket) -> str:
    json_format_data = json.dumps(data).encode('utf-8')
    s.sendall(json_format_data)
    response = s.recv(1024)
    response = json.loads(response)
    return response


# encrypt plain_text using MD5 hash and store as user's secret key.
def md5_hash(plain_text: str) -> str:
    digest = hashes.Hash(hashes.MD5())
    digest.update(bytes(plain_text, encoding='utf-8'))
    hashed_pass = digest.finalize()
    base64_hashed_pass_bytes = base64.b64encode(hashed_pass)
    hashed_pass_string = base64_hashed_pass_bytes.decode("ascii")
    return hashed_pass_string