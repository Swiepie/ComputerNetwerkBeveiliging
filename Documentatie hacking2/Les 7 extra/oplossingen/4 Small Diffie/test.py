import json
import hashlib

data = json.load(open("challenge.json"))
p, g = data["p"], data["g"]
ya, yb = data["Y_alice"], data["Y_bob"]
ct = bytes.fromhex(data["encrypted_flag"])

# --------------------------------------------------
# Stap 1: discrete log van Y_alice met baby-step giant-step
#   p is maar 40 bit  =>  sqrt(p) ~ 2^20 stappen
# --------------------------------------------------
m = int(p ** 0.5) + 1
table = {}
cur = 1
for j in range(m):
    table.setdefault(cur, j)
    cur = cur * g % p

factor = pow(g, -m, p)
gamma = ya
xa = None
for i in range(m + 1):
    if gamma in table:
        xa = i * m + table[gamma]
        break
    gamma = gamma * factor % p
assert xa is not None and pow(g, xa, p) == ya
print(f"[+] X_alice = {xa}")

# --------------------------------------------------
# Stap 2: gedeelde sleutel K = Y_bob^X_alice mod p
# --------------------------------------------------
K = pow(yb, xa, p)
print(f"[+] K = {K}")

# --------------------------------------------------
# Stap 3: keystream en XOR
# --------------------------------------------------
keystream = b""
i = 0
while len(keystream) < len(ct):
    keystream += hashlib.sha256(f"{K}:{i}".encode()).digest()
    i += 1
flag = bytes(a ^ b for a, b in zip(ct, keystream))
print("[+] Flag:", flag.decode(errors="replace"))
