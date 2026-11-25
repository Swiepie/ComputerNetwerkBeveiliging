"""
Oefening: "Free keys" (Les 5)
==============================
AANVAL: Common modulus attack.

HERKENNING in de opgave:
 - Hetzelfde bericht M is twee keer versleuteld met DEZELFDE modulus n,
   maar met twee verschillende (en onderling ondeelbare) publieke
   exponenten e1 en e2.
   C1 = M^e1 mod n
   C2 = M^e2 mod n
 - Zodra je "dezelfde n, andere e" ziet staan -> denk common modulus!

WISKUNDE:
 Omdat gcd(e1, e2) = 1, bestaan er (via Extended Euclid) gehele getallen
 a en b (een van beide negatief) zodat:
       a*e1 + b*e2 = 1
 Dan geldt:
       C1^a * C2^b = M^(a*e1) * M^(b*e2) = M^(a*e1 + b*e2) = M^1 = M (mod n)
 Een negatieve exponent los je op door de modulaire inverse van de
 ciphertext te nemen: C^(-k) mod n = (C^-1)^k mod n.

 Belangrijk: deze aanval heeft GEEN kennis van p, q of d nodig!

TEGENMAATREGEL: gebruik nooit dezelfde n voor meerdere sleutelparen/
gebruikers, en voeg altijd padding (bv. OAEP) toe aan M.
"""


def egcd(a: int, b: int):
    """Uitgebreid algoritme van Euclides: geeft (g, x, y) met a*x + b*y = g."""
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> int:
    g, a, b = egcd(e1, e2)
    assert g == 1, "e1 en e2 moeten onderling ondeelbaar zijn (gcd = 1)"
    print(f"[+] a = {a}, b = {b}   (controle: a*e1 + b*e2 = {a * e1 + b * e2})")

    # Negatieve exponent oplossen via modulaire inverse van de ciphertext
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


if __name__ == "__main__":
    import json

    with open("challenge.json") as f:
        data = json.load(f)

    m = common_modulus_attack(data["n"], data["e1"], data["c1"], data["e2"], data["c2"])
    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print("[+] Teruggevonden bericht:", flag.decode(errors="replace"))
