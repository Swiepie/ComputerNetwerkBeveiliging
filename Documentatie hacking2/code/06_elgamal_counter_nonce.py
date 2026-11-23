"""
Oefening: "Fresh" (Les 6)
===========================
AANVAL: ElGamal - voorspelbare (opeenvolgende) nonce k in plaats van
een echt willekeurige nonce.

HERKENNING in de opgave:
 - Twee ElGamal-ciphertexts (C1_a, C2_a) en (C1_b, C2_b) met
   VERSCHILLENDE C1, dus op het eerste gezicht geen klassieke
   nonce-hergebruik (zoals in oefening 4).
 - Maar: de nonces blijken een TELLER te zijn die telkens met een klein
   getal (hier: 1) verhoogd wordt in plaats van willekeurig gekozen.
   k_b = k_a + delta, met delta klein (bv. 0 < delta < 10^6).
 - Zo'n patroon herken je bv. aan commentaar/context "counter", "teller",
   of gewoon omdat de opgave de naam van de aanval verklapt:
   "a counter is not a nonce".

WISKUNDE:
   C1_a = g^k_a mod p,   C1_b = g^(k_a + delta) mod p
   => C1_b / C1_a = g^delta mod p

 Stap 1: bereken ratio = C1_b * C1_a^-1 mod p, en zoek met brute force
         (kleine delta!) de waarde delta waarvoor g^delta mod p = ratio.
 Stap 2: y^k_a afleiden uit het gekende bericht:
         y^k_a = C2_bekend * M_bekend^-1 mod p
 Stap 3: y^k_b = y^k_a * y^delta mod p
 Stap 4: M_flag = C2_flag * (y^k_b)^-1 mod p

TEGENMAATREGEL: gebruik een cryptografisch veilige, volledig
willekeurige nonce k, nooit een teller of een voorspelbaar patroon.
"""

import json
import sys


def vind_klein_verschil(ratio: int, g: int, p: int, max_delta: int = 1_000_000) -> int:
    """Brute force: zoek delta zodat g^delta mod p == ratio (enkel haalbaar
    als delta klein is, anders zou je Baby-Step-Giant-Step nodig hebben)."""
    cur = 1
    for delta in range(max_delta):
        if cur == ratio:
            return delta
        cur = cur * g % p
    raise ValueError("geen klein verschil gevonden binnen max_delta pogingen")


def elgamal_counter_nonce_attack(p: int, g: int, y: int, m_known: bytes,
                                  c1_known: int, c2_known: int,
                                  c1_flag: int, c2_flag: int) -> bytes:
    # Stap 1: verschil tussen de nonces
    ratio = (c1_flag * pow(c1_known, -1, p)) % p
    delta = vind_klein_verschil(ratio, g, p)
    print(f"[+] k_flag - k_known = {delta}  (teller is maar met {delta} verhoogd!)")

    # Stap 2: y^k_known uit het gekende bericht
    m_known_int = int.from_bytes(m_known, "big")
    y_tot_k_known = (c2_known * pow(m_known_int, -1, p)) % p

    # Stap 3: y^k_flag = y^k_known * y^delta
    y_tot_k_flag = (y_tot_k_known * pow(y, delta, p)) % p

    # Stap 4: bericht terugvinden
    m_flag_int = (c2_flag * pow(y_tot_k_flag, -1, p)) % p
    return m_flag_int.to_bytes((m_flag_int.bit_length() + 7) // 8, "big")


if __name__ == "__main__":
    pad = sys.argv[1] if len(sys.argv) > 1 else "ElGamal_challenge.json"
    with open(pad) as f:
        data = json.load(f)

    flag = elgamal_counter_nonce_attack(
        p=data["p"], g=data["g"], y=data["y"],
        m_known=data["known_plaintext"].encode(),
        c1_known=data["cipher_known"][0], c2_known=data["cipher_known"][1],
        c1_flag=data["cipher_flag"][0], c2_flag=data["cipher_flag"][1],
    )
    print("[+] Teruggevonden bericht:", flag.decode(errors="replace"))
