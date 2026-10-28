import socket
import re

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50001

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # 1. Alles ontvangen tot de prompt (kan in meerdere stukken binnenkomen)
    banner = b""
    while b"Submit the transaction" not in banner:
        chunk = s.recv(4096)
        if not chunk:
            break
        banner += chunk
    banner = banner.decode()
    print(banner)

    # 2. Hex-string uit de banner halen met een regex (robuuster dan split)
    match = re.search(r'([0-9a-fA-F]{20,})', banner)
    if not match:
        raise ValueError("Geen hex-ciphertext gevonden in banner!")
    ct_hex = match.group(1)
    ciphertext = bytes.fromhex(ct_hex)
    print("Ciphertext lengte:", len(ciphertext))

    # 3. Bekend plaintext-sjabloon, op basis van format.json
    known_plaintext = b'{"from":"alice","to":"bobby","amount": "100"}'
    print("Plaintext lengte:", len(known_plaintext))
    assert len(known_plaintext) == len(ciphertext), \
        f"Lengte komt niet overeen: {len(known_plaintext)} vs {len(ciphertext)}"

    # 4. Keystream terugrekenen
    keystream = xor_bytes(ciphertext, known_plaintext)
    print("Keystream:", keystream.hex())

    # 5. Eigen vervalste boodschap — zelfde lengte vereist!
    my_plaintext = b'{"from":"alice","to":"bob","amount": "100"}'
    assert len(my_plaintext) == len(keystream), \
        f"Lengte van jouw bericht moet exact {len(keystream)} zijn, is nu {len(my_plaintext)}"

    # 6. Versleutelen met dezelfde keystream
    forged_ciphertext = xor_bytes(keystream, my_plaintext)
    forged_hex = forged_ciphertext.hex()
    print("Te versturen (hex):", forged_hex)

    # 7. Versturen naar de server
    s.sendall(forged_hex.encode() +  b'\n')
    response = s.recv(4096)
    print("Server antwoord:", response.decode())