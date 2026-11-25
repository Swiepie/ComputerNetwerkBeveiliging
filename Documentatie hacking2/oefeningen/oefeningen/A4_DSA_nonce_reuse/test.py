import hashlib
import json

# --------------------------------------------------
# 1. Parameters laden
# --------------------------------------------------
data = json.load(open("dsa1_challenge.json"))
p, q, g, y = data["p"], data["q"], data["g"], data["y"]
(m1, r1, s1), (m2, r2, s2) = [
    (sg["message"], sg["r"], sg["s"]) for sg in data["signatures"]
]

# --------------------------------------------------
# 2. Controles
# --------------------------------------------------
assert r1 == r2, "r verschilt: geen nonce-hergebruik"
r = r1
print("[+] r1 == r2  ->  dezelfde nonce k is gebruikt")
print("[+] g^q mod p == 1:", pow(g, q, p) == 1)


# --------------------------------------------------
# 3. Hashfunctie H(m) = int(sha256(m)) mod q
# --------------------------------------------------
def H(m):
    return int.from_bytes(hashlib.sha256(m.encode()).digest(), "big") % q


h1, h2 = H(m1), H(m2)

# --------------------------------------------------
# 4. Nonce k en prive-sleutel x
# --------------------------------------------------
k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q
x = ((s1 * k - h1) * pow(r, -1, q)) % q

print(f"[+] k = {k}")
print(f"[+] x = {x}")
print("[+] g^x mod p == y:", pow(g, x, p) == y)
print("[+] controle 2e vergelijking:", (s2 * k - h2 - x * r) % q == 0)

# --------------------------------------------------
# 5. Keystream en XOR
# --------------------------------------------------
ct = bytes.fromhex(data["encrypted_flag"])
keystream = b""
i = 0
while len(keystream) < len(ct):
    keystream += hashlib.sha256(f"{x}:{i}".encode()).digest()
    i += 1

flag = bytes(a ^ b for a, b in zip(ct, keystream))
print("[+] Flag:", flag.decode(errors="replace"))