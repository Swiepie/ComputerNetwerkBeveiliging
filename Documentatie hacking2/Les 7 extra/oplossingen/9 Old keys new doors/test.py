import json
import hashlib
from server import step3, step5     # server.py staat naast dit script

data = json.load(open("challenge.json"))
Ks = data["Ks_old"]
ticket = data["recorded_ticket_step3"]

def keystream(K, n):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{K}:{i}".encode()).digest()
        i += 1
    return out[:n]

def E(K, m: bytes) -> str:
    return bytes(a ^ b for a, b in zip(m, keystream(K, len(m)))).hex()

# --------------------------------------------------
# Stap 3 opnieuw afspelen: B kan niet zien dat dit een oude ticket is
# --------------------------------------------------
antwoord4 = step3(ticket)                      # E(Ks, N2)
raw = bytes.fromhex(antwoord4)
N2 = int(bytes(a ^ b for a, b in zip(raw, keystream(Ks, len(raw)))).decode())
print(f"[+] N2 = {N2}")

# --------------------------------------------------
# Stap 5: Ks is bekend, dus we kunnen f(N2) = N2 + 1 zelf versleutelen
# --------------------------------------------------
print("[+]", step5(E(Ks, str(N2 + 1).encode())))
