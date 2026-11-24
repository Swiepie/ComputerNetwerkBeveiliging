import json
import math

data = json.load(open("challenge.json"))
n, e = data["n"], data["e"]
m, s_f, c = data["message_as_int"], data["faulty_signature"], data["c"]

# --------------------------------------------------
# Een correcte handtekening voldoet aan s^e = m (mod n), dus ook mod p en mod q.
# De fout zat alleen in de q-tak:
#     s_f^e = m   (mod p)     <- klopt nog
#     s_f^e != m  (mod q)     <- klopt niet meer
# Dus p deelt (s_f^e - m), maar q niet  =>  gcd geeft p
# --------------------------------------------------
p = math.gcd(pow(s_f, e, n) - m, n)
assert 1 < p < n
q = n // p
print(f"[+] p = {p}")
print(f"[+] q = {q}")

d = pow(e, -1, (p - 1) * (q - 1))
M = pow(c, d, n)
print("[+] Flag:", M.to_bytes((M.bit_length() + 7) // 8, "big").decode())
