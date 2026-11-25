"""
Oefening: "Shifting sand" (Les 5)
=================================
AANVAL: Factorisatie van n via Pollard's rho, omdat n te klein is.

HERKENNING in de opgave:
 - Enkel n en e zijn gegeven (klassieke RSA-encryptie), geen p, q of d.
 - n is "klein" (hier maar ~65 bits). Een moderne computer kan zo'n n
   in minder dan een seconde factoriseren.
 - Als n groot genoeg is (>= 2048 bit), werkt deze aanval NIET meer:
   dan moet je naar een andere zwakte zoeken (zie stappenplan).

WISKUNDE:
 - RSA is enkel veilig zolang het factoriseren van n = p*q onhaalbaar is.
 - Pollard's rho vindt in verwachte tijd O(n^(1/4)) een niet-triviale
   factor van n, gebruik makend van de "cyclus" (schildpad-en-haas truc)
   van de iteratie x -> x^2 + c mod n.
 - Zodra p en q gekend zijn:
       phi(n) = (p-1)(q-1)
       d = e^-1 mod phi(n)      (modulaire inverse, zie Extended Euclid)
 - Dan is M = C^d mod n voor elk blok C van de ciphertext.

TEGENMAATREGEL: gebruik een n van minstens 2048 bit (zie slides:
tabel "minimum key sizes considered safe").
"""

import json
import math
import random


def pollard_rho(n: int) -> int:
    """Geeft een niet-triviale factor van n terug (Pollard's rho)."""
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
        if d != n:                       # d == n betekent "mislukte poging", probeer opnieuw
            return d


def kraak_rsa_klein_modulus(challenge_path: str = "challenge.json") -> bytes:
    with open(challenge_path, "r") as f:
        challenge = json.load(f)

    n = challenge["n"]
    e = challenge["e"]
    ciphertext = challenge["ciphertext"]
    block_size = challenge["block_size"]
    original_length = challenge["original_length"]

    # Stap 1: n factoriseren
    p = pollard_rho(n)
    q = n // p
    assert p * q == n, "factorisatie klopt niet"
    print(f"[+] n gefactoriseerd: p = {p}")
    print(f"[+]                   q = {q}")

    # Stap 2: private exponent d berekenen
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print(f"[+] phi(n) = {phi}")
    print(f"[+] d      = {d}")

    # Stap 3: blok per blok ontcijferen
    plaintext = bytearray()
    for c in ciphertext:
        m = pow(c, d, n)
        plaintext.extend(m.to_bytes(block_size, byteorder="big"))

    return bytes(plaintext[:original_length])


if __name__ == "__main__":
    bericht = kraak_rsa_klein_modulus()
    print("\n[+] Ontcijferd bericht:")
    print(bericht.decode("utf-8"))
