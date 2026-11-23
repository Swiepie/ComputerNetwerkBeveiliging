"""
Oefening: "Double entry" (Les 6)
===================================
AANVAL: DSA - hergebruik van de per-bericht nonce k bij het ondertekenen.

HERKENNING in de opgave:
 - Twee verschillende berichten, elk voorzien van een DSA-handtekening
   (r, s).
 - De r-component van beide handtekeningen is EXACT GELIJK.
   r = (g^k mod p) mod q hangt alleen af van k (en de globale
   parameters), niet van het bericht. Dus gelijke r => gelijke k!
 - Dit is een klassieke, zeer bekende DSA-fout (vergelijkbaar met de
   Sony PS3-hack en de Android Bitcoin-wallet bugs).

WISKUNDE:
   s1 = k^-1 (H(m1) + x*r) mod q
   s2 = k^-1 (H(m2) + x*r) mod q
 Aftrekken geeft:
   s1 - s2 = k^-1 (H(m1) - H(m2)) mod q
   => k = (H(m1) - H(m2)) * (s1 - s2)^-1 mod q

 Zodra k gekend is, volgt de private key x uit:
   s1 = k^-1 (H(m1) + x*r) mod q
   => x = (s1*k - H(m1)) * r^-1 mod q

TEGENMAATREGEL: genereer k cryptografisch veilig en uniek per
handtekening (of gebruik deterministische DSA volgens RFC 6979, waar k
afhangt van het bericht EN de private key, zodat hergebruik onmogelijk
wordt zonder x te kennen).
"""

import hashlib
import json


def H(m: str, q: int) -> int:
    """Hash van het bericht, gereduceerd modulo q (zoals in de opgave gedefinieerd)."""
    return int.from_bytes(hashlib.sha256(m.encode()).digest(), "big") % q


def dsa_nonce_reuse_attack(p: int, q: int, g: int, y: int,
                            m1: str, r1: int, s1: int,
                            m2: str, r2: int, s2: int):
    assert r1 == r2, "r1 != r2: er is GEEN nonce-hergebruik, deze aanval werkt hier niet"
    r = r1
    print("[+] r1 == r2  ->  dezelfde nonce k werd gebruikt voor beide handtekeningen")
    print("[+] sanity check g^q mod p == 1:", pow(g, q, p) == 1)

    h1, h2 = H(m1, q), H(m2, q)

    # Stap 1: nonce k terugvinden
    k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q

    # Stap 2: private key x terugvinden
    x = ((s1 * k - h1) * pow(r, -1, q)) % q

    print(f"[+] k = {k}")
    print(f"[+] x (private key) = {x}")
    print("[+] controle g^x mod p == y:", pow(g, x, p) == y)
    return k, x


def xor_keystream_decrypt(x: int, ct: bytes) -> bytes:
    """Specifiek voor deze opgave: de vlag is versleuteld met een
    XOR-keystream afgeleid van de (nu gekende) private key x."""
    keystream = b""
    i = 0
    while len(keystream) < len(ct):
        keystream += hashlib.sha256(f"{x}:{i}".encode()).digest()
        i += 1
    return bytes(a ^ b for a, b in zip(ct, keystream))


if __name__ == "__main__":
    data = json.load(open("dsa1_challenge.json"))
    p, q, g, y = data["p"], data["q"], data["g"], data["y"]
    sig1, sig2 = data["signatures"]

    k, x = dsa_nonce_reuse_attack(
        p, q, g, y,
        sig1["message"], sig1["r"], sig1["s"],
        sig2["message"], sig2["r"], sig2["s"],
    )

    ct = bytes.fromhex(data["encrypted_flag"])
    flag = xor_keystream_decrypt(x, ct)
    print("[+] Teruggevonden bericht:", flag.decode(errors="replace"))
