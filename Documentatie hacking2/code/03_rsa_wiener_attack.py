"""
Oefening: "Sports car desire" (Les 5)
=======================================
AANVAL: Wiener's attack (kettingbreuken) voor een te kleine private
exponent d.

HERKENNING in de opgave:
 - n en e zijn gegeven, e is ONGEWOON GROOT (bijna even groot als n,
   in plaats van het typische e = 65537).
 - Dit is een signaal dat d waarschijnlijk klein gekozen is, want e en d
   zijn elkaars "tegenpolen": als men d expres klein kiest (voor snelheid),
   wordt e automatisch heel groot modulo phi(n).
 - Vuistregel (zie slides, hoofdstuk "Mathematical attacks"): als
   d < n^(1/4) ... dan kan d efficient teruggevonden worden.

WISKUNDE:
 Wiener toont aan dat als d < (1/3) * n^(1/4), de breuk e/n een
 convergent is van de kettingbreuk-ontwikkeling van e/n. Door alle
 convergenten k/d te overlopen, vind je snel de juiste d:
    1) ontbind e/n in een kettingbreuk
    2) bereken alle convergenten (k, d)
    3) test of phi = (e*d - 1) / k een geheel getal is
    4) los p en q op via s = p+q = n - phi + 1  en  (p-q)^2 = s^2 - 4n

TEGENMAATREGEL: kies d NOOIT klein. Gebruik een standaard e
(bv. 65537) en laat d normaal groot zijn (ongeveer even groot als n).
"""

import math


def kettingbreuk(a: int, b: int):
    """Kettingbreukontwikkeling van a/b als lijst van gehele quotienten."""
    res = []
    while b:
        res.append(a // b)
        a, b = b, a % b
    return res


def convergenten(cf):
    """Genereert alle convergenten k/d van een kettingbreuk."""
    h0, h1, k0, k1 = 0, 1, 1, 0
    for a in cf:
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        yield h1, k1


def wiener_attack(e: int, n: int):
    """Geeft (d, p, q) terug, of None als de aanval mislukt."""
    for k, d in convergenten(kettingbreuk(e, n)):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1                  # s = p + q
        disc = s * s - 4 * n             # (p - q)^2
        if disc >= 0:
            r = math.isqrt(disc)
            if r * r == disc and (s + r) % 2 == 0:
                p, q = (s + r) // 2, (s - r) // 2
                if p * q == n:
                    return d, p, q
    return None


if __name__ == "__main__":
    import json

    with open("challenge-3.json") as f:
        data = json.load(f)
    n, e, c = data["n"], data["e"], data["c"]

    result = wiener_attack(e, n)
    if result is None:
        raise SystemExit("[-] Wiener-aanval faalt: d is waarschijnlijk niet klein genoeg")

    d, p, q = result
    print(f"[+] d ({d.bit_length()} bit) = {d}")
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")

    m = pow(c, d, n)
    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print("[+] Teruggevonden bericht:", flag.decode())
