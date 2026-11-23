"""
EXTRA VOORBEELD (niet in de oefeningen, wel in de cursus - zie slide
"Two threats to larger key sizes exist": p en q moeten "nearly the same
number of digits" hebben, maar NIET te dicht bij elkaar liggen!)
=====================================================================
AANVAL: Fermat-factorisatie wanneer p en q te dicht bij elkaar liggen.

HERKENNING in de opgave:
 - Enkel n (en e) gegeven, GEEN hints over de grootte van p of q.
 - Als |p - q| erg klein is (bv. als een sleutelgenerator p = q + klein
   getal kiest, een implementatiefout), dan is sqrt(n) ongeveer gelijk
   aan zowel p als q.

WISKUNDE:
 Schrijf n = p*q met p > q. Stel a = (p+q)/2 en b = (p-q)/2, dan:
     n = a^2 - b^2   <=>   a^2 - n = b^2
 Begin met a = ceil(sqrt(n)) en verhoog a stap voor stap tot a^2 - n
 een perfect kwadraat is. Dit gaat SNEL als b (dus |p-q|) klein is,
 want het aantal stappen is ongeveer b.
   p = a + b
   q = a - b

TEGENMAATREGEL: kies p en q onafhankelijk en willekeurig uit een groot
interval (niet gewoon "twee priemgetallen vlak na elkaar").
"""

import math


def fermat_factorization(n: int, max_pogingen: int = 1_000_000):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_pogingen):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a + b, a - b
        a += 1
    return None


def is_prime(n: int, rondes: int = 20) -> bool:
    """Eenvoudige Miller-Rabin priemtest (geen externe libraries nodig)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    import random
    for _ in range(rondes):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def volgende_priem(n: int) -> int:
    if n % 2 == 0:
        n += 1
    while not is_prime(n):
        n += 2
    return n


if __name__ == "__main__":
    # Demo: we bouwen zelf een "zwakke" RSA-sleutel met p en q dicht bij elkaar.
    import random

    random.seed(1)
    basis = random.getrandbits(512) | 1
    p = volgende_priem(basis)
    q = volgende_priem(p + random.randint(1, 10_000))   # q ligt heel dicht bij p!
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    geheim = b"cns{fermat_needs_close_primes}"
    m = int.from_bytes(geheim, "big")
    c = pow(m, e, n)

    print(f"[+] n heeft {n.bit_length()} bits, |p-q| is klein (opzettelijk zwak)")
    resultaat = fermat_factorization(n)
    assert resultaat is not None, "Fermat-factorisatie mislukt (p en q liggen niet dicht genoeg)"
    p_gevonden, q_gevonden = resultaat
    assert p_gevonden * q_gevonden == n

    phi2 = (p_gevonden - 1) * (q_gevonden - 1)
    d2 = pow(e, -1, phi2)
    m2 = pow(c, d2, n)
    bericht = m2.to_bytes((m2.bit_length() + 7) // 8, "big")

    print(f"[+] p = {p_gevonden}")
    print(f"[+] q = {q_gevonden}")
    print("[+] Teruggevonden bericht:", bericht.decode())
