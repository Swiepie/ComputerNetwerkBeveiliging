import json
import sys

# --------------------------------------------------
# Data inlezen uit JSON (standaard challenge.json,
# of een ander pad als argument: python3 script.py bestand.json)
# --------------------------------------------------
pad = sys.argv[1] if len(sys.argv) > 1 else "ElGamal_challenge.json"
with open(pad, "r") as f:
    data = json.load(f)

p = data["p"]
g = data["g"]
y = data["y"]
m_known = int.from_bytes(data["known_plaintext"].encode(), "big")
c1_known, c2_known = data["cipher_known"]
c1_flag, c2_flag = data["cipher_flag"]

# --------------------------------------------------
# Stap 1: verschil tussen de nonces zoeken
# c1_flag / c1_known = g^(k2 - k1), met d = k2 - k1 klein
# --------------------------------------------------
ratio = (c1_flag * pow(c1_known, -1, p)) % p
d, cur = None, 1
for i in range(1_000_000):
    if cur == ratio:
        d = i
        break
    cur = cur * g % p
assert d is not None, "geen klein verschil gevonden"
print(f"[+] k2 - k1 = {d}")

# --------------------------------------------------
# Stap 2: y^k1 uit het bekende bericht, daarna y^k2 = y^k1 * y^d
# --------------------------------------------------
s1 = (c2_known * pow(m_known, -1, p)) % p
s2 = (s1 * pow(y, d, p)) % p

# --------------------------------------------------
# Stap 3: flag ontsleutelen
# --------------------------------------------------
m_flag = (c2_flag * pow(s2, -1, p)) % p
print("[+] Flag:", m_flag.to_bytes((m_flag.bit_length() + 7) // 8, "big").decode())