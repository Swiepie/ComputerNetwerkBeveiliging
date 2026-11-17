import json
import math
import random

# --------------------------------------------------
# Challenge laden (challenge.json moet naast dit script staan)
# --------------------------------------------------

with open("challenge.json", "r") as f:
    challenge = json.load(f)

n = challenge["n"]
e = challenge["e"]
ciphertext = challenge["ciphertext"]
block_size = challenge["block_size"]
original_length = challenge["original_length"]


# --------------------------------------------------
# Stap 1: n factoriseren met Pollard's rho
# --------------------------------------------------

def pollard_rho(n):
    """Geeft een niet-triviale factor van n terug."""
    if n % 2 == 0:
        return 2
    while True:
        c = random.randrange(1, n)
        x = y = random.randrange(2, n)
        d = 1
        while d == 1:
            x = (x * x + c) % n          # schildpad: 1 stap
            y = (y * y + c) % n          # haas: 2 stappen
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


p = pollard_rho(n)
q = n // p
assert p * q == n

print(f"[+] n gefactoriseerd: p = {p}, q = {q}")


# --------------------------------------------------
# Stap 2: privésleutel d berekenen
# --------------------------------------------------

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)          # modulair inverse van e (Python 3.8+)

print(f"[+] Privé-exponent d = {d}")


# --------------------------------------------------
# Stap 3: ontcijferen
# --------------------------------------------------

plaintext = bytearray()
for c in ciphertext:
    m = pow(c, d, n)
    plaintext.extend(m.to_bytes(block_size, byteorder="big"))

plaintext = plaintext[:original_length]

print("\n[+] Ontcijferd bericht:")
print("---------------------")
print(plaintext.decode("utf-8"))