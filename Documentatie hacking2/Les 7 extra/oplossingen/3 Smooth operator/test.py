import json
from sympy import factorint

data = json.load(open("challenge.json"))
p, g, y, c1, c2 = data["p"], data["g"], data["y"], data["c1"], data["c2"]

# --------------------------------------------------
# Stap 1: p - 1 factoriseren: alle factoren zijn klein
# --------------------------------------------------
fac = factorint(p - 1)
print("[+] p - 1 =", " * ".join(str(f) for f in fac))

# --------------------------------------------------
# Stap 2: discrete log in elke kleine subgroep (baby-step giant-step)
#   x mod f  met  (g^((p-1)/f))^(x mod f) = y^((p-1)/f)
# --------------------------------------------------
def bsgs(base, target, order):
    m = int(order ** 0.5) + 1
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * base % p
    factor = pow(base, -m, p)
    gamma = target
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    raise ValueError("geen oplossing")

residues, moduli = [], []
for f, mult in fac.items():
    assert mult == 1
    h = pow(g, (p - 1) // f, p)
    t = pow(y, (p - 1) // f, p)
    xi = bsgs(h, t, f)
    residues.append(xi); moduli.append(f)
    print(f"    x = {xi} (mod {f})")

# --------------------------------------------------
# Stap 3: Chinese reststelling -> x mod (p-1)
# --------------------------------------------------
M = p - 1
x = sum(r * (M // mi) * pow(M // mi, -1, mi) for r, mi in zip(residues, moduli)) % M
assert pow(g, x, p) == y
print(f"[+] priveesleutel x = {x}")

# --------------------------------------------------
# Stap 4: ontcijferen  m = c2 / c1^x
# --------------------------------------------------
m = (c2 * pow(pow(c1, x, p), -1, p)) % p
print("[+] Flag:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode())
