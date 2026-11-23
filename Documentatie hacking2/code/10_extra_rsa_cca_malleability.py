"""
EXTRA VOORBEELD (zie slide "Chosen ciphertext attack (CCA)")
===============================================================
AANVAL: Chosen Ciphertext Attack (CCA) - RSA zonder padding is
"malleable": je kan een ciphertext wiskundig vermenigvuldigen zonder
de inhoud te kennen, en dit misbruiken als je toegang hebt tot een
"decryptie-orakel" (bv. een server die ciphertexts voor je ontcijfert,
behalve de ene die je probeert te kraken).

HERKENNING:
 - Je hebt GEEN private key, maar wel toegang tot een functie/server die
   WILLEKEURIGE ciphertexts voor jou ontcijfert (behalve exact de
   doelwit-ciphertext zelf).
 - Er wordt GEEN padding (zoals OAEP) gebruikt.

WISKUNDE:
 RSA is multiplicatief homomorf:
     E(M1) * E(M2) mod n = E(M1 * M2 mod n)
 Gegeven C = M^e mod n (het doelwit, dat je niet rechtstreeks mag
 laten ontcijferen):
   1) kies een willekeurig getal s (bv. s = 2) en bereken
          X = (C * s^e) mod n   =  (M*s)^e mod n
   2) laat het orakel X ontcijferen (X is een ANDERE ciphertext dan C,
      dus het orakel ontcijfert dit zonder argwaan):
          Y = X^d mod n  =  M*s mod n
   3) M = Y * s^-1 mod n

TEGENMAATREGEL: gebruik OAEP-padding. Daarmee geldt de vermenigvuldig-
eigenschap niet langer (de padding bevat willekeurigheid), waardoor een
gewijzigde ciphertext na decryptie als "ongeldig" verworpen wordt.
"""


def cca_attack(c_doelwit: int, e: int, n: int, decryptie_orakel) -> int:
    """decryptie_orakel: functie die een ciphertext (!= c_doelwit) ontcijfert."""
    s = 2  # eender welk getal, zolang gcd(s, n) == 1
    x = (c_doelwit * pow(s, e, n)) % n
    assert x != c_doelwit, "kies een andere s, anders herkent het orakel het doelwit"

    y = decryptie_orakel(x)              # y = M * s mod n
    m = (y * pow(s, -1, n)) % n
    return m


if __name__ == "__main__":
    # ---- demo-opstelling: we simuleren een kwetsbare RSA-server ----
    p, q = 10007, 10079
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    d = pow(e, -1, phi)

    geheim_bericht = 424242           # dit is wat de aanvaller NIET mag weten
    c_doelwit = pow(geheim_bericht, e, n)

    def kwetsbare_server(ciphertext: int) -> int:
        """Ontcijfert alles, behalve letterlijk de doelwit-ciphertext zelf
        (zoals een orakel dat weigert het 'echte' bericht te verklappen,
        maar niets controleert op gewijzigde varianten)."""
        if ciphertext == c_doelwit:
            raise PermissionError("dit specifieke bericht mag niet ontcijferd worden")
        return pow(ciphertext, d, n)

    teruggevonden = cca_attack(c_doelwit, e, n, kwetsbare_server)
    print(f"[+] Origineel geheim bericht : {geheim_bericht}")
    print(f"[+] Teruggevonden via CCA    : {teruggevonden}")
    assert teruggevonden == geheim_bericht
    print("[+] Succesvol! De server heeft het geheim gelekt zonder het zelf te ontcijferen.")
