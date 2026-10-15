import socket
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
#pwn tools zijn beter hiervoor
import json
HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50006

key = get_random_bytes(16)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    #s.sendall(message.encode())
    data = s.recv(2048)
    datas = s.recv(2048)

print('Received', (data))
print('Received', (datas))