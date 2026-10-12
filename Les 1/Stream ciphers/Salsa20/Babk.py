import socket
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
#pwn tools zijn beter hiervoor
import json
HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50001

jsonfile = json.load(open('format.json'))
key = get_random_bytes(16)

for i in range (10000):
    while i > 0:
        salt = get_random_bytes(16)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            #cipher = Salsa20(key=b'my_secret_key')
            message = 'c7917b667a714c23ee79e8bea58ff717061291b530f93e06d5c36fbc14e44063de163d28792dcb3466a01d0dec1e2f6ea4139b0204'
            #encrypted_message = cipher.encrypt(message)

            s.sendall(message.encode())
            data = s.recv(2048)
        print('Received', repr(data))