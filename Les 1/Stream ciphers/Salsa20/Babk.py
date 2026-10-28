import socket
HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50001

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = s.recv(2048)
print('Received', repr(data))