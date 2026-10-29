import socket
HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50010

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall("hi")
    data = s.recv(2048)
print('Received', repr(data))