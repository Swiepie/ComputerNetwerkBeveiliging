import socket
import re
import time

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50001

def attempt(byte_index, bit_index):
    """Verbind, haal ciphertext op, flip één bit, stuur, retourneer serverantwoord."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        banner = b""
        while b"Submit the transaction" not in banner:
            chunk = s.recv(4096)
            if not chunk:
                break
            banner += chunk
        banner_str = banner.decode(errors='replace')
        match = re.search(r'Your pending transaction:\s*([0-9a-fA-F]+)', banner_str)
        if not match:
            return "NO_CIPHERTEXT"
        ct = bytes.fromhex(match.group(1))
        if len(ct) != 53:
            return f"BAD_LENGTH_{len(ct)}"

        forged = bytearray(ct)
        forged[byte_index] ^= (1 << bit_index)
        s.sendall(forged.hex().encode() + b'\n')
        response = s.recv(4096).decode(errors='replace').strip()
        return response

# ------------------------------------------------------------------
# We weten: byte 30 = 'b' (ontvanger). We willen de ontvanger NIET
# veranderen, alleen het bedrag. Het bedrag zit waarschijnlijk in
# bytes 46-52. We proberen alle bits in bytes 33 t/m 52.
# ------------------------------------------------------------------
print("Scannen van bytes 33 t/m 52 op zoek naar het bedrag...")
print("We laten de ontvanger (byte 30-32) met rust.\n")

found = False
for byte_index in range(33, 53):
    for bit_index in range(8):
        resp = attempt(byte_index, bit_index)
        # Toon alleen als het antwoord niet "Invalid" is
        if "Invalid" not in resp and "Error" not in resp and resp != "NO_CIPHERTEXT":
            print(f"[!] byte {byte_index:2d}, bit {bit_index}: {resp}")
            if "100 EUR" in resp or "100" in resp:
                print(f"\n[!!!] MOGELIJK DOEL BEREIKT: byte {byte_index}, bit {bit_index}")
                print("Antwoord:", resp)
                found = True
        # Optioneel: toon voortgang per byte
    print(f"  byte {byte_index:2d} gedaan")
    time.sleep(0.05)

if not found:
    print("\nGeen enkele bit-flip in 33-52 gaf een ander bedrag. Probeer ook bytes 0-29.")