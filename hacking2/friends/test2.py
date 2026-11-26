"""
Oefening: "group chat" & "better group chat" (Les 5)
=======================================================
AANVAL: Hastad broadcast attack (via de Chinese reststelling, CRT).

HERKENNING in de opgave:
 - Hetzelfde bericht M is naar meerdere (>= e) ontvangers gestuurd,
   elk met hun EIGEN modulus n_i, maar ALLEMAAL met dezelfde (kleine!)
   publieke exponent e (typisch e = 3).
   C_i = M^e mod n_i
 - Kleine e (3, 5, 7, 17, ...) + hetzelfde bericht naar >= e ontvangers
   + geen padding op M  =>  denk Hastad!

WISKUNDE:
 Via CRT kan je uit de e congruenties
      X = M^e mod n_1
      X = M^e mod n_2
      ...
      X = M^e mod n_e
 (met alle n_i onderling ondeelbaar) een unieke X < n_1*n_2*...*n_e
 reconstrueren met X = M^e.
 Omdat M < elke n_i, geldt M^e < n_1*n_2*...*n_e, dus X = M^e EXACT
 (geen modulo-reductie nodig!). Je kan dus gewoon de gehele e-de
 machtswortel van X nemen om M terug te vinden.

 Opmerking: zelfs als de drie C_i toevallig identiek zijn (zoals in het
 "group chat"-voorbeeld), verandert dat niets aan de aanval: je moet
 gewoon drie keer dezelfde congruentie meenemen in de CRT (dat mag,
 zolang de n_i onderling ondeelbaar zijn).

TEGENMAATREGEL: gebruik nooit een klein e zonder willekeurige padding
(OAEP) op het bericht, en/of gebruik een unieke M per ontvanger.
"""

import re


def integer_nth_root(x: int, n: int) -> int:
    """Gehele n-de machtswortel van x via binaire zoektocht (naar beneden afgerond)."""
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


def crt(residuen, moduli):
    """Chinese reststelling: combineer X = residuen[i] mod moduli[i]."""
    N = 1
    for ni in moduli:
        N *= ni
    X = 0
    for ci, ni in zip(residuen, moduli):
        Ni = N // ni
        X += ci * Ni * pow(Ni, -1, ni)
    return X % N, N


def hastad_broadcast_attack(ciphertexts, moduli, e: int) -> bytes:
    assert len(ciphertexts) >= e, f"er zijn minstens e={e} (ciphertext, n)-paren nodig"

    X, N = crt(ciphertexts[:e], moduli[:e])
    print(f"[+] CRT-resultaat X = M^{e} mod N (met N = product van de moduli)")

    M = integer_nth_root(X, e)
    assert M ** e == X, "geen exacte e-de machtswortel gevonden: check e of padding"
    print(f"[+] M^{e} is een exacte macht -> M teruggevonden zonder enige private key")

    return M.to_bytes((M.bit_length() + 7) // 8, "big")


if __name__ == "__main__":
    # Werkt zowel voor "group chat" (ciphertexts.txt/public_keys.txt)
    # als "better group chat" (ciphertexts-2.txt/public_keys-2.txt):
    # geef gewoon de juiste bestandsnamen mee.
    import sys

    ct_file = sys.argv[1] if len(sys.argv) > 1 else "ciphertexts.txt"
    key_file = sys.argv[2] if len(sys.argv) > 2 else "public_keys.txt"

    c = [int(x) for x in re.findall(r"c\d+\s*=\s*(\d+)", open(ct_file).read())]
    n = [int(x) for x in re.findall(r"n\s*=\s*(\d+)", open(key_file).read())]
    e_list = [int(x) for x in re.findall(r"e\s*=\s*(\d+)", open(key_file).read())]
    e = e_list[0]
    assert all(ei == e for ei in e_list), "alle e-waarden moeten gelijk zijn voor deze aanval"

    flag = hastad_broadcast_attack(c, n, e)
    print("[+] Teruggevonden bericht:", flag.decode(errors="replace"))
