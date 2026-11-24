import json
import hashlib

d = json.load(open("challenge.json"))
p = d["p"]
ya, yd1 = d["Y_A (Alice -> Darth)"], d["Y_D1 (Darth -> Bob)"]
yb, yd2 = d["Y_B (Bob -> Darth)"], d["Y_D2 (Darth -> Alice)"]
xd1, xd2 = d["darth_private_X_D1"], d["darth_private_X_D2"]
ca = bytes.fromhex(d["msg_alice_to_bob"])
cb = bytes.fromhex(d["msg_bob_to_alice"])

def keystream(K, n):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{K}:{i}".encode()).digest()
        i += 1
    return out[:n]

# --------------------------------------------------
# Darth rekent zelf beide sleutels uit:
#   K2 = (Y_A)^X_D2 mod p   (gedeeld met Alice)
#   K1 = (Y_B)^X_D1 mod p   (gedeeld met Bob)
# --------------------------------------------------
K2 = pow(ya, xd2, p)
K1 = pow(yb, xd1, p)

print("[+] Alice -> Bob :", bytes(a ^ b for a, b in zip(ca, keystream(K2, len(ca)))).decode())
print("[+] Bob -> Alice :", bytes(a ^ b for a, b in zip(cb, keystream(K1, len(cb)))).decode())
