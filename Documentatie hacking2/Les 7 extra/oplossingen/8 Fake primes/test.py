import json
import hashlib
import random

data = json.load(open("challenge.json"))
cands = data["candidates"]
ct = bytes.fromhex(data["encrypted_flag"])

# --------------------------------------------------
# Miller-Rabin (zoals op de slides):
#   n - 1 = 2^k * q  met q oneven
#   n is 'mogelijk priem' als a^q = 1 (mod n)  of  a^(2^j * q) = n - 1 voor een j in [0, k-1]
# --------------------------------------------------
def miller_rabin(n, rondes=40):
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    k, q = 0, n - 1
    while q % 2 == 0:
        q //= 2
        k += 1
    for _ in range(rondes):
        a = random.randrange(2, n - 1)
        x = pow(a, q, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(k - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False        # zeker samengesteld
    return True                 # priem met kans 1 - (1/4)^rondes

# Ter vergelijking: de simpele Fermat-test trapt in Carmichael-getallen
def fermat(n, rondes=40):
    return all(pow(random.randrange(2, n - 1), n - 1, n) == 1 for _ in range(rondes))

priem = sorted(x for x in cands if miller_rabin(x))
fermat_ok = [x for x in cands if fermat(x)]
print(f"[+] Miller-Rabin: {len(priem)} priemgetallen")
print(f"[+] Fermat laat er {len(fermat_ok)} door (dus {len(fermat_ok) - len(priem)} Carmichael-getallen)")

key = ",".join(str(x) for x in priem)
keystream = b""
i = 0
while len(keystream) < len(ct):
    keystream += hashlib.sha256(f"{key}:{i}".encode()).digest()
    i += 1
print("[+] Flag:", bytes(a ^ b for a, b in zip(ct, keystream)).decode(errors="replace"))
