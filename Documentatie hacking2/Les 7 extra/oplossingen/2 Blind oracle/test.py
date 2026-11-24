import json
from oracle import decrypt          # oracle.py staat naast dit script

data = json.load(open("challenge.json"))
n, e, c = data["n"], data["e"], data["c"]

# --------------------------------------------------
# Eigenschap: E(M1) * E(M2) = E(M1 * M2)
# Kies M2 = 2:  X = c * 2^e mod n = (2M)^e mod n   (X != c, dus de oracle weigert niet)
# --------------------------------------------------
X = (c * pow(2, e, n)) % n
Y = decrypt(X)                      # Y = 2M mod n
print("[+] oracle gaf 2M terug")

# --------------------------------------------------
# M = Y / 2 mod n
# --------------------------------------------------
m = (Y * pow(2, -1, n)) % n
print("[+] Flag:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode())
