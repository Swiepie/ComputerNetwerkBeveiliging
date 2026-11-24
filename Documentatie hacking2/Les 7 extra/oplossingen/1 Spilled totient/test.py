import json
import math

# --------------------------------------------------
# Challenge laden
# --------------------------------------------------
data = json.load(open("challenge.json"))
n, e, c, phi = data["n"], data["e"], data["c"], data["phi"]

# --------------------------------------------------
# Stap 1: phi(n) = (p-1)(q-1) = n - (p+q) + 1   =>   s = p + q
# --------------------------------------------------
s = n - phi + 1
print(f"[+] p + q = {s}")

# --------------------------------------------------
# Stap 2: p en q zijn de nulpunten van  X^2 - s*X + n = 0
#         discriminant = s^2 - 4n = (p - q)^2
# --------------------------------------------------
disc = s * s - 4 * n
r = math.isqrt(disc)
assert r * r == disc, "discriminant is geen kwadraat"
p, q = (s + r) // 2, (s - r) // 2
assert p * q == n
print(f"[+] p = {p}")
print(f"[+] q = {q}")

# --------------------------------------------------
# Stap 3: d = e^-1 mod phi, ontcijferen
# --------------------------------------------------
d = pow(e, -1, phi)
m = pow(c, d, n)
print("[+] Flag:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode())
