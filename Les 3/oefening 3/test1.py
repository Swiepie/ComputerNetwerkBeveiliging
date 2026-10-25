import socket
import hashlib

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50006

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

data = ""
while "CURRENT CODE:" not in data:
    data += s.recv(4096).decode(errors="replace")
print(data)

# haal de hex-code uit wat we ontvingen
current_hex = data.split("CURRENT CODE:")[1].strip().splitlines()[0].strip()
print("huidige code:", current_hex)

# bereken de volgende code
next_hex = hashlib.sha256(bytes.fromhex(current_hex)).hexdigest()
print("volgende code:", next_hex)

# stuur terug
s.sendall((next_hex + "\n").encode())

response = s.recv(4096).decode(errors="replace")
print("server antwoord:", response)

s.close()