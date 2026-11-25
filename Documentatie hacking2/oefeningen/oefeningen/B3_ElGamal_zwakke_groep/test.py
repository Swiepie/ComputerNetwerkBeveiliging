"""
EXTRA VOORBEELD (zie slides "Discrete logarithms" en "Security of
ElGamal encryption: cryptoanalysis" / DSA)
=============================================================
AANVAL: Baby-Step Giant-Step (BSGS) om een discrete logaritme te
berekenen wanneer de groep (bv. q in ElGamal/DSA) te klein is.

HERKENNING:
 - ElGamal- of DSA-parameters met een te kleine p of q (bv. minder dan
   ~60-80 bit i.p.v. de vereiste >= 300 decimale cijfers, zie slide
   "Security of ElGamal encryption: cryptoanalysis").
 - Je kan dan de private key X rechtstreeks berekenen uit het publieke
   Y = g^X mod p, ZONDER nonce-hergebruik of andere fouten nodig te
   hebben: de parameters zelf zijn gewoon te zwak.

WISKUNDE (Baby-Step Giant-Step, O(sqrt(q)) in plaats van O(q)):
 Schrijf X = i*m + j, met m = ceil(sqrt(q)), 0 <= i,j < m.
   Y = g^X = g^(i*m) * g^j
   => Y * g^(-j) = (g^m)^i

 Stap 1 (baby steps): bouw een tabel {g^j mod p : j} voor j = 0..m-1.
 Stap 2 (giant steps): loop over i = 0..m-1 en zoek of
         Y * (g^-m)^i mod p in die tabel voorkomt.
 Zodra een match gevonden is: X = i*m + j.

TEGENMAATREGEL: gebruik een voldoende grote groep (q >= 300 decimale
cijfers, zoals vermeld in de slides), zodat BSGS/Pollard-rho-DL
onhaalbaar wordt.
"""

import math
import hashlib
def generate_keystream(x: int, length: int) -> bytes:
    keystream = b""
    counter = 0
    while len(keystream) < length:
        # Maak de string f"{x}:{counter}", hash hem met SHA-256 en neem de bytes (.digest())
        data = f"{x}:{counter}".encode('utf-8')
        keystream += hashlib.sha256(data).digest()
        counter += 1
    # Snijd af op de exacte lengte van de vlag
    return keystream[:length]

def baby_step_giant_step(g: int, y: int, p: int, q: int):
    """Los y = g^x mod p op voor x in [0, q), met orde q van g."""
    m = math.isqrt(q) + 1

    # Stap 1: baby steps
    tabel = {}
    e = 1
    for j in range(m):
        tabel[e] = j
        e = (e * g) % p

    # Stap 2: giant steps
    factor = pow(g, -m, p)          # g^(-m) mod p
    gamma = y
    for i in range(m):
        if gamma in tabel:
            return i * m + tabel[gamma]
        gamma = (gamma * factor) % p
    return None

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(
            f"XOR requires equal lengths: {len(a)} != {len(b)}"
        )
    return bytes(x ^ y for x, y in zip(a, b))

if __name__ == "__main__":
    # Demo: bewust te klein gekozen p/q (NOOIT doen in de praktijk!)
    p = 220492046321       # een (klein) priemgetal (2^31 - 1, Mersenne-priem)
    g = 6
    q = p - 1                # vereenvoudigd voor deze demo

    y = 180946332061     # dit is het publieke deel

    flag = "1a92657d997a68278e5565cf2b39fa9263d5a6a91ce5e12441e149"

    gevonden_x = baby_step_giant_step(g, y, p, q)
    print(f"[+] Teruggevonden private key x = {gevonden_x}")

    flag_bytes = bytes.fromhex(flag)

    # Genereer de keystream op basis van de omschrijving
    keystream = generate_keystream(gevonden_x, len(flag_bytes))

    # Ontsleutel de vlag via XOR met de echte keystream
    decrypted_flag = xor_bytes(keystream, flag_bytes)

    print(f"[+] Decrypted flag: {decrypted_flag.decode('utf-8')}")

