import json
from server import sign, verify     # server.py staat naast dit script

data = json.load(open("challenge.json"))
n, e, target = data["n"], data["e"], data["target_as_int"]

# --------------------------------------------------
# Ruwe RSA is multiplicatief:  sign(m1) * sign(m2) = sign(m1 * m2)  (mod n)
# Kies m1 = 2  en  m2 = target / 2 mod n   =>   m1 * m2 = target
# Geen van beide is TARGET zelf, dus de server tekent ze gewoon.
# --------------------------------------------------
m1 = 2
m2 = (target * pow(2, -1, n)) % n
s1, s2 = sign(m1), sign(m2)

forged = (s1 * s2) % n
assert pow(forged, e, n) == target
print("[+] vervalste handtekening geldig")
print("[+] Flag:", verify(forged).decode())
