import socket
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
#pwn tools zijn beter hiervoor
import json
HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50006

key = get_random_bytes(16)

import hashlib

current_code_hex = "5c320c96d3b7c941393aad37fb33f50eea6d9ed2e7e18a1da7a8ef3134e3e09b"
next_code = hashlib.sha256(bytes.fromhex(current_code_hex)).hexdigest()
print(next_code)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    #s.sendall(message.encode())
    data = s.recv(2048)
    datas = s.recv(2048)
    data2 = s.recv(2048)

print('Received', (data))
print('Received', (datas))
print('Received', (data2))