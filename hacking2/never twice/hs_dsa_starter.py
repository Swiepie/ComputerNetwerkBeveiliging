#!/usr/bin/env python3
"""Starter for the Never Twice challenge."""
import hashlib
import json

d = json.load(open("hs_dsa_challenge.json"))
p, q, g, y = d["p"], d["q"], d["g"], d["y"]
first, second = d["signatures"]          # each has "order", "message", "r", "s"

c1_known = "1042"
c2_known = "1047"

c1_flag = 684669703048682486433020488167931324204894256025
c2_flag = 34309642084432353727733577755205435164127238569


s1 = 684669703048682486433020488167931324204894256025
s2 = 34309642084432353727733577755205435164127238569

r1 = 264758081940145221269961151969374732581278060168
r2 = 812126763398423349420390259680298945375006579135

m1 = "Order 1042: transfer 10 EUR to Alice"
m2 = "Order 1047: transfer 25 EUR to Bob"
def H(message: str) -> int:
    """The hash that is signed."""
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % q


def decrypt_flag(x: int) -> bytes:
    """Decrypts the flag, given the private signing key x."""
    ct = bytes.fromhex(d["encrypted_flag"])
    ks, i = b"", 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(f"{x}:{i}".encode()).digest()
        i += 1
    return bytes(c ^ s for c, s in zip(ct, ks))



import json
import sys

h1, h2 = H(m1), H(m2)
h12, h22 = H(c1_known), H(c2_known)
#g^delta mod p = ratio.


i = 1

grote_k = pow(y, i, q)

print(pow(h1, 1042, q))
print(pow(g, 1042+5, p))

print(pow(g, 1042, p)/pow(g, 1042+5, p))




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
                                  c1_flag: int, c2_flag: int, ratio) -> bytes:
    # Stap 1: verschil tussen de nonces

    delta = vind_klein_verschil(ratio, g, p)
    print(f"[+] k_flag - k_known = {delta}  (teller is maar met {delta} verhoogd!)")

    return
    # Stap 2: y^k_known uit het gekende bericht
    m_known_int = int.from_bytes(m_known, "big")
    y_tot_k_known = (c2_known * pow(m_known_int, -1, p)) % p

    # Stap 3: y^k_flag = y^k_known * y^delta
    y_tot_k_flag = (y_tot_k_known * pow(y, delta, p)) % p

    # Stap 4: bericht terugvinden
    m_flag_int = (c2_flag * pow(y_tot_k_flag, -1, p)) % p
    return m_flag_int.to_bytes((m_flag_int.bit_length() + 7) // 8, "big")


v = vind_klein_verschil(pow(h1, 1042, q)/pow(h2,1047,q), g, p)
print(v)

#print(pow(g, 1042, p)/pow(g, 1042+5, p))