"""
EXTRA VOORBEELD (zie slide "Efficient operation using the public key":
"Small values for e are vulnerable to attack if no padding is used for M!")
===========================================================================
AANVAL: Rechtstreekse e-de machtswortel bij kleine e en GEEN padding,
als het bericht M zelf klein genoeg is (M^e < n). Dit is de simpelste
variant: er is zelfs maar EEN ciphertext/ontvanger nodig (in
tegenstelling tot Hastad, waar je e ontvangers nodig hebt).

HERKENNING:
 - e is klein (3, 5, 7, ...)
 - Het bericht M is kort (bv. een korte vlag), zodat M^e < n sowieso
   geldt, en er dus GEEN modulo-reductie gebeurt: C = M^e (gewoon,
   zonder "mod n" effect).

WISKUNDE:
 Als M^e < n, dan is C = M^e mod n gewoon gelijk aan M^e (er wordt nooit
 "omgeklapt"). Je hoeft dus alleen een gehele e-de machtswortel te nemen.

TEGENMAATREGEL: voeg altijd padding toe (OAEP), zodat M altijd bijna
even groot is als n en M^e >> n.
"""


def integer_nth_root(x: int, n: int) -> int:
    if x == 0:
        return 0
    lo, hi = 0, 1 << (x.bit_length() // n + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n < x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def small_e_cube_root_attack(c: int, e: int) -> bytes:
    m = integer_nth_root(c, e)
    assert m ** e == c, "C is GEEN exacte e-de macht: M^e >= n, dus deze eenvoudige aanval werkt niet (probeer Hastad met meerdere ontvangers i.p.v.)"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


if __name__ == "__main__":
    # Demo met zelfgemaakte, bewust zwakke parameters (n ruim groter dan M^e)
    n = (1 << 1024) + 7   # een willekeurig groot getal, enkel als bovengrens nodig
    e = 3
    geheim = b"cns{no_padding_cube_root}"
    m = int.from_bytes(geheim, "big")
    assert m ** e < n, "demo-bericht is te lang voor deze n, kies een kortere n of M"
    c = m ** e  # merk op: GEEN "% n" nodig, want m^e < n

    bericht = small_e_cube_root_attack(c, e)
    print("[+] Teruggevonden bericht:", bericht.decode())
