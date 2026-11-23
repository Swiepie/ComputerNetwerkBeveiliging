"""
Oefening: "Assymetric nonsense" (Les 5)
=========================================
AANVAL: ElGamal - hergebruik van de eenmalige sleutel (nonce) k.

HERKENNING in de opgave:
 - Twee versleutelde berichten (C1_a, C2_a) en (C1_b, C2_b) met ElGamal.
 - C1 = g^k mod p is voor BEIDE berichten exact hetzelfde getal.
   => dat betekent dat dezelfde k gebruikt is (want C1 hangt alleen
      af van k, niet van het bericht M of de ontvanger).
 - Als je van een van de twee berichten de plaintext al kent
   ("known_plaintext"), kan je de tweede plaintext zonder private key
   terugvinden!

WISKUNDE:
   C1      = g^k mod p                (zelfde voor beide berichten)
   C2_bekend = M_bekend * y^k mod p
   C2_flag   = M_flag    * y^k mod p

   Stap 1: y^k = C2_bekend * M_bekend^-1 mod p
   Stap 2: M_flag = C2_flag * (y^k)^-1 mod p

TEGENMAATREGEL (zie slides "Security of ElGamal encryption: key reuse"):
 gebruik voor elk bericht een NIEUWE, willekeurige k.
"""


def elgamal_nonce_reuse_attack(p: int, m_known: bytes, c1_known: int, c2_known: int,
                                c1_flag: int, c2_flag: int) -> bytes:
    assert c1_known == c1_flag, "C1 verschilt: de nonce k is NIET hergebruikt, aanval werkt niet"
    print("[+] C1 is identiek voor beide berichten -> nonce k is hergebruikt")

    m_known_int = int.from_bytes(m_known, "big")

    # y^k herleiden uit het gekende bericht
    y_tot_k = (c2_known * pow(m_known_int, -1, p)) % p

    # onbekend bericht terugvinden met diezelfde y^k
    m_flag_int = (c2_flag * pow(y_tot_k, -1, p)) % p

    return m_flag_int.to_bytes((m_flag_int.bit_length() + 7) // 8, "big")


if __name__ == "__main__":
    import json

    with open("challenge-4.json") as f:
        data = json.load(f)

    flag = elgamal_nonce_reuse_attack(
        p=data["p"],
        m_known=data["known_plaintext"].encode(),
        c1_known=data["cipher_known"][0],
        c2_known=data["cipher_known"][1],
        c1_flag=data["cipher_flag"][0],
        c2_flag=data["cipher_flag"][1],
    )
    print("[+] Teruggevonden bericht:", flag.decode(errors="replace"))
