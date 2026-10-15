import socket
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
#pwn tools zijn beter hiervoor
import json
HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50003

key = get_random_bytes(16)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    #s.sendall(message.encode())
    data = s.recv(2048)
    received_data = data
    clean_text = received_data.decode('utf-8')

# 2. Verwijder eventuele lege regels/spaties aan het begin en einde
    clean_text = clean_text.strip()
print('Received', (clean_text))