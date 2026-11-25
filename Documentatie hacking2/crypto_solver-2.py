#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto_solver.py
=================
Eén samengevoegd script dat alle losse oefening-scripts uit "code/" en
"Les 7 extra/oplossingen/" combineert tot één automatische kraker.

GEBRUIK:
    Zet dit script gewoon in dezelfde map als challenge.json en run:
        python3 crypto_solver.py
    (het pakt automatisch "challenge.json" uit de huidige map)

    Een ander bestand/pad gebruiken kan ook nog steeds:
        python3 crypto_solver.py pad/naar/ander_bestand.json
        python3 crypto_solver.py pad/naar/challenge.json --max-delta 2000000

Het script:
  1) leest de JSON in,
  2) herkent automatisch of het om RSA, ElGamal of DSA gaat (en welke
     specifieke zwakte van toepassing is, puur op basis van welke velden
     in de JSON aanwezig zijn),
  3) voert de bijbehorende aanval uit en print het teruggevonden bericht
     / de flag, met tussenstappen zoals in de originele oefen-scripts.

OEFENINGEN MET EEN DECRYPT/SIGN/STEP-FUNCTIE (Blind oracle, Forged receipt,
Old keys new doors):
  Die hebben in de praktijk helemaal geen "levende server" nodig - de oracle
  is gewoon een los bestand (oracle.py / server.py) dat naast challenge.json
  in dezelfde map staat. Dit script importeert dat bestand automatisch (als
  het er staat) en voert de bijpassende aanval uit:
    - Blind oracle:       RSA-blinding (CCA): c verblinden met r^e zodat de
                           oracle niet ziet dat je eigenlijk c ontcijfert.
    - Forged receipt:     multiplicatieve handtekening-vervalsing:
                           sign(r) * sign(target * r^-1) = sign(target).
    - Old keys new doors: replay-aanval met de gelekte oude sessiesleutel.
  Staat het oracle.py/server.py bestand er niet bij (bv. je hebt enkel het
  kale JSON-bestand), dan kan dit script het uiteraard niet oplossen en
  krijg je een duidelijke melding in plaats van een gegokt antwoord.

Samengevoegd uit:
  code/01_rsa_klein_modulus_pollard_rho.py
  code/02_rsa_common_modulus.py
  code/03_rsa_wiener_attack.py
  code/04_elgamal_nonce_reuse.py
  code/05_rsa_hastad_broadcast.py (als los bruikbare functie, geen auto-dispatch
      want dit heeft meerdere bestanden/ontvangers nodig, geen losse JSON)
  code/06_elgamal_counter_nonce.py
  code/07_dsa_nonce_reuse.py
  code/08_extra_rsa_fermat_factorization.py
  code/09_extra_rsa_small_e_cube_root.py
  code/10_extra_rsa_cca_malleability.py (als losse functie, oracle nodig)
  code/11_extra_discrete_log_bsgs.py
  Les 7 extra/oplossingen/1 Spilled totient/test.py
  Les 7 extra/oplossingen/3 Smooth operator/test.py   (Pohlig-Hellman)
  Les 7 extra/oplossingen/4 Small Diffie/test.py
  Les 7 extra/oplossingen/5 Darth in the middle/test.py
  Les 7 extra/oplossingen/7 Glitch/test.py
  Les 7 extra/oplossingen/8 Fake primes/test.py
"""

import argparse
import hashlib
import importlib.util
import json
import math
import os
import random
import sys

try:
    from sympy import factorint as _sympy_factorint
    _HAS_SYMPY = True
except ImportError:
    _HAS_SYMPY = False


# ======================================================================
# Generieke wiskundige hulpfuncties (uit code/*.py)
# ======================================================================

def egcd(a: int, b: int):
    """Uitgebreid algoritme van Euclides: geeft (g, x, y) met a*x + b*y = g."""
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def pollard_rho(n: int) -> int:
    """Geeft een niet-triviale factor van n terug (Pollard's rho)."""
    if n % 2 == 0:
        return 2
    while True:
        c = random.randrange(1, n)
        x = y = random.randrange(2, n)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def fermat_factorization(n: int, max_pogingen: int = 2_000_000):
    """Werkt snel als p en q dicht bij elkaar liggen."""
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


def miller_rabin(n: int, rondes: int = 40) -> bool:
    """Miller-Rabin priemtest (zoals op de slides)."""
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    k, q = 0, n - 1
    while q % 2 == 0:
        q //= 2
        k += 1
    for _ in range(rondes):
        a = random.randrange(2, n - 1)
        x = pow(a, q, n)
        if x in (1, n - 1):
            continue
        for _ in range(k - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def fermat_test(n: int, rondes: int = 40) -> bool:
    """Eenvoudige Fermat-priemtest - trapt in Carmichael-getallen."""
    if n < 4:
        return n in (2, 3)
    return all(pow(random.randrange(2, n - 1), n - 1, n) == 1 for _ in range(rondes))


def kettingbreuk(a: int, b: int):
    res = []
    while b:
        res.append(a // b)
        a, b = b, a % b
    return res


def convergenten(cf):
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
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            r = math.isqrt(disc)
            if r * r == disc and (s + r) % 2 == 0:
                p, q = (s + r) // 2, (s - r) // 2
                if p * q == n:
                    return d, p, q
    return None


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


def bsgs(g: int, y: int, p: int, order: int):
    """Baby-Step Giant-Step: los y = g^x mod p op voor x in [0, order)."""
    m = math.isqrt(order) + 1
    tabel = {}
    cur = 1
    for j in range(m):
        tabel.setdefault(cur, j)
        cur = cur * g % p
    factor = pow(g, -m, p)
    gamma = y
    for i in range(m + 1):
        if gamma in tabel:
            return i * m + tabel[gamma]
        gamma = gamma * factor % p
    return None


def factorint(n: int) -> dict:
    """Factoriseer n in priemfactoren. Gebruikt sympy indien beschikbaar,
    anders een eenvoudige Pollard-rho/trial-division fallback."""
    if _HAS_SYMPY:
        return dict(_sympy_factorint(n))

    factors = {}
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if miller_rabin(m):
            factors[m] = factors.get(m, 0) + 1
            continue
        # kleine factoren eerst (snel), dan pollard rho
        f = None
        for klein in range(2, 100000):
            if m % klein == 0:
                f = klein
                break
        if f is None:
            f = pollard_rho(m)
        stack.append(f)
        stack.append(m // f)
    return factors


def keystream(key, length: int) -> bytes:
    """sha256(f'{key}:0') || sha256(f'{key}:1') || ... , afgekapt op length bytes."""
    out = b""
    i = 0
    while len(out) < length:
        out += hashlib.sha256(f"{key}:{i}".encode()).digest()
        i += 1
    return out[:length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def int_to_bytes(m: int) -> bytes:
    if m == 0:
        return b"\x00"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def print_flag(label: str, data: bytes):
    try:
        print(f"[+] {label}: {data.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"[+] {label} (raw bytes, niet UTF-8 decodeerbaar): {data!r}")


# ======================================================================
# Live oracle/server-module naast de JSON opzoeken en inladen
# ======================================================================

def inspect_sibling_module(json_path: str, filename: str = "server.py"):
    """Hulpfunctie om een onbekend protocol te verkennen: toont welke functies
    een naastliggende oracle.py/server.py aanbiedt, met hun signatuur en
    docstring. Handig als er bv. een step6() of iets anders onverwachts bij zit
    waarvoor nog geen specifieke aanval in dit script staat."""
    import inspect
    module = load_sibling_module(json_path, filename)
    if module is None:
        print(f"[-] Geen {filename} gevonden naast {json_path}.")
        return
    print(f"[*] Functies gevonden in {filename}:")
    for name, obj in vars(module).items():
        if inspect.isfunction(obj) and not name.startswith("_"):
            try:
                sig = inspect.signature(obj)
            except (TypeError, ValueError):
                sig = "(...)"
            doc = inspect.getdoc(obj) or ""
            print(f"    {name}{sig}   # {doc}")


def load_sibling_module(json_path: str, filename: str):
    """Laadt oracle.py / server.py als het in dezelfde map staat als de
    opgegeven JSON. Geeft None terug als het bestand er niet is (dan kan
    dit script de bijbehorende aanval simpelweg niet uitvoeren)."""
    folder = os.path.dirname(os.path.abspath(json_path))
    path = os.path.join(folder, filename)
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location(filename[:-3], path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ======================================================================
# Aanvallen die een lokale oracle.py/server.py aanroepen
# ======================================================================

def rsa_blinding_attack(n, e, c, decrypt_fn):
    """'Blind oracle': decrypt() weigert enkel de EXACTE ciphertext c.
    Trucje: verblind c met r^e mod n voor je decrypt() aanroept, en haal
    r er daarna weer af. decrypt((c*r^e) mod n) = (m*r) mod n."""
    r = random.randrange(2, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randrange(2, n - 1)
    c_blind = (c * pow(r, e, n)) % n
    print(f"[*] Verblind c met r = {r}  ->  c_blind = c * r^e mod n")
    m_blind = decrypt_fn(c_blind)
    print("[+] Oracle gaf decrypt(c_blind) terug (dus niet decrypt(c) zelf)")
    m = (m_blind * pow(r, -1, n)) % n
    return int_to_bytes(m)


def rsa_forge_signature_attack(n, target, sign_fn):
    """'Forged receipt': sign() weigert enkel het EXACTE target-bericht.
    Trucje: kies m1 = r en m2 = target * r^-1 mod n (geen van beide gelijk
    aan target), laat beide tekenen en vermenigvuldig de handtekeningen:
    sign(m1)*sign(m2) = (m1*m2)^d = target^d = sign(target)."""
    while True:
        r = random.randrange(2, n - 1)
        if math.gcd(r, n) != 1:
            continue
        m1 = r
        m2 = (target * pow(r, -1, n)) % n
        if m1 % n != target % n and m2 % n != target % n:
            break
    print(f"[*] m1 = r = {m1}")
    print(f"[*] m2 = target * r^-1 mod n = {m2}")
    s1 = sign_fn(m1)
    s2 = sign_fn(m2)
    forged = (s1 * s2) % n
    print(f"[+] Vervalste handtekening = sign(m1) * sign(m2) mod n = {forged}")
    return forged


def kdc_replay_attack(ks_old: str, recorded_ticket_hex: str, step3_fn, step5_fn):
    """'Old keys new doors': B onthoudt geen oude sessiesleutels, dus je
    kan het opgevangen ticket uit stap 3 gewoon opnieuw afspelen. Omdat de
    sessiesleutel erin de GELEKTE oude sleutel is, kun je B's antwoord
    (E(Ks, N2)) ontcijferen, N2+1 berekenen en stap 5 netjes afronden."""
    resp_hex = step3_fn(recorded_ticket_hex)
    resp = bytes.fromhex(resp_hex)
    n2_str = xor_bytes(resp, keystream(ks_old, len(resp))).decode()
    n2 = int(n2_str)
    print(f"[+] N2 (uit replay van het opgevangen ticket) = {n2}")
    f_n2 = str(n2 + 1).encode()
    resp2_hex = xor_bytes(f_n2, keystream(ks_old, len(f_n2))).hex()
    return step5_fn(resp2_hex)


# ======================================================================
# RSA-aanvallen
# ======================================================================

def rsa_common_modulus_attack(n, e1, c1, e2, c2):
    g, a, b = egcd(e1, e2)
    assert g == 1, "e1 en e2 moeten onderling ondeelbaar zijn (gcd = 1)"
    print(f"[+] a = {a}, b = {b}   (controle: a*e1 + b*e2 = {a * e1 + b * e2})")
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def rsa_spilled_totient_attack(n, phi):
    s = n - phi + 1  # s = p + q
    print(f"[+] p + q = {s}  (uit phi = n - (p+q) + 1)")
    disc = s * s - 4 * n
    r = math.isqrt(disc)
    assert r * r == disc, "discriminant is geen perfect kwadraat"
    p, q = (s + r) // 2, (s - r) // 2
    assert p * q == n
    return p, q


def rsa_glitch_crt_attack(n, e, m, faulty_sig):
    """Eén foute CRT-handtekening: s_f^e == m (mod p) maar niet (mod q)
    => gcd(s_f^e - m, n) geeft p."""
    p = math.gcd(pow(faulty_sig, e, n) - m, n)
    assert 1 < p < n, "gcd gaf geen niet-triviale factor - deze JSON lijkt geen 'Glitch'-geval"
    q = n // p
    return p, q


def rsa_single_ciphertext_attack(n, e, c, max_delta=1_000_000):
    """Probeert, in volgorde, alle aanvallen die werken met enkel (n, e, c):
    Wiener (kleine d), Fermat (p en q dicht bij elkaar), Pollard rho (kleine n),
    en rechtstreekse e-de machtswortel (kleine e, geen padding)."""

    # 1) Wiener attack: snel, probeer altijd eerst.
    print("[*] Probeer Wiener attack (kleine private exponent d)...")
    result = wiener_attack(e, n)
    if result is not None:
        d, p, q = result
        print(f"[+] Wiener attack geslaagd! d ({d.bit_length()} bit) = {d}")
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        m = pow(c, d, n)
        return int_to_bytes(m)

    # 2) Rechtstreekse e-de machtswortel: snel, probeer als e klein is.
    if e <= 1_000_000:
        print(f"[*] Probeer rechtstreekse {e}-de machtswortel (kleine e, geen padding)...")
        m = integer_nth_root(c, e)
        if m ** e == c:
            print(f"[+] c is een EXACTE {e}-de macht -> M^e < n, geen private key nodig!")
            return int_to_bytes(m)

    # 3) Fermat-factorisatie: snel als p en q dicht bij elkaar liggen.
    print("[*] Probeer Fermat-factorisatie (p en q dicht bij elkaar)...")
    fres = fermat_factorization(n, max_pogingen=2_000_000)
    if fres is not None:
        p, q = fres
        if p * q == n and p != 1 and q != 1:
            print(f"[+] Fermat-factorisatie geslaagd!")
            print(f"[+] p = {p}")
            print(f"[+] q = {q}")
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            return int_to_bytes(m)

    # 4) Pollard rho: werkt voor een "kleine" n (grof: < ~90 bit).
    if n.bit_length() <= 100:
        print("[*] Probeer Pollard's rho factorisatie (kleine n)...")
        try:
            p = pollard_rho(n)
            q = n // p
            if p * q == n:
                print(f"[+] Pollard's rho geslaagd!")
                print(f"[+] p = {p}")
                print(f"[+] q = {q}")
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)
                m = pow(c, d, n)
                return int_to_bytes(m)
        except Exception:
            pass

    return None


def rsa_block_attack(n, e, ciphertext, block_size, original_length):
    """Kleine modulus, meerdere blokken (zie '01_rsa_klein_modulus_pollard_rho.py')."""
    print("[*] n lijkt klein -> Pollard's rho factorisatie...")
    p = pollard_rho(n)
    q = n // p
    assert p * q == n, "factorisatie klopt niet"
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print(f"[+] d = {d}")
    plaintext = bytearray()
    for cblock in ciphertext:
        m = pow(cblock, d, n)
        plaintext.extend(m.to_bytes(block_size, byteorder="big"))
    return bytes(plaintext[:original_length])


def solve_rsa(data, args):
    print("=" * 70)
    print("HERKEND: RSA")
    print("=" * 70)

    n = data["n"]

    # --- common modulus: zelfde n, twee verschillende e's ---
    if {"e1", "e2", "c1", "c2"} <= data.keys():
        print("[*] Patroon herkend: dezelfde n, twee verschillende e -> COMMON MODULUS")
        m = rsa_common_modulus_attack(n, data["e1"], data["c1"], data["e2"], data["c2"])
        print_flag("Teruggevonden bericht", int_to_bytes(m))
        return

    # --- phi gegeven: spilled totient ---
    if "phi" in data:
        print("[*] Patroon herkend: phi(n) is gegeven -> SPILLED TOTIENT")
        e, c = data["e"], data["c"]
        p, q = rsa_spilled_totient_attack(n, data["phi"])
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        d = pow(e, -1, data["phi"])
        m = pow(c, d, n)
        print_flag("Flag", int_to_bytes(m))
        return

    # --- foute CRT-handtekening (Glitch) ---
    if "faulty_signature" in data:
        print("[*] Patroon herkend: foute CRT-handtekening -> GLITCH (p via gcd)")
        e = data["e"]
        m = data["message_as_int"]
        s_f = data["faulty_signature"]
        c = data["c"]
        p, q = rsa_glitch_crt_attack(n, e, m, s_f)
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        d = pow(e, -1, (p - 1) * (q - 1))
        M = pow(c, d, n)
        print_flag("Flag", int_to_bytes(M))
        return

    # --- geblokte ciphertext: klein n ---
    if "ciphertext" in data and isinstance(data["ciphertext"], list):
        print("[*] Patroon herkend: meerdere blokken ciphertext -> KLEINE MODULUS (Pollard rho)")
        bericht = rsa_block_attack(
            n, data["e"], data["ciphertext"], data["block_size"], data["original_length"]
        )
        print_flag("Ontcijferd bericht", bericht)
        return

    # --- forged-signature stijl (geen c, wel een target + opdracht om te tekenen) ---
    if "target_as_int" in data and "c" not in data:
        print("[*] Patroon herkend: 'forge a signature' (bv. Forged receipt)")
        server = load_sibling_module(args.challenge_json, "server.py")
        if server is not None and hasattr(server, "sign"):
            print("[*] server.py gevonden naast de JSON -> multiplicatieve forgery-aanval...")
            forged = rsa_forge_signature_attack(n, data["target_as_int"], server.sign)
            if hasattr(server, "verify"):
                result = server.verify(forged)
                print(f"[+] server.verify(vervalste handtekening) -> {result}")
            else:
                print(f"[+] Vervalste handtekening: {forged}")
        else:
            print("[-] Geen server.py gevonden naast deze JSON (nodig voor sign()/verify()).")
            print("    Zet server.py in dezelfde map als challenge.json om dit op te lossen.")
        return

    # --- standaard geval: enkel n, e, c ---
    if "e" in data and "c" in data:
        e, c = data["e"], data["c"]
        bericht = rsa_single_ciphertext_attack(n, e, c, max_delta=args.max_delta)
        if bericht is None:
            oracle = load_sibling_module(args.challenge_json, "oracle.py")
            if oracle is not None and hasattr(oracle, "decrypt"):
                print("[*] oracle.py gevonden naast de JSON -> probeer blinding-aanval (CCA)...")
                try:
                    bericht = rsa_blinding_attack(n, e, c, oracle.decrypt)
                except Exception as exc:
                    print(f"[-] blinding-aanval mislukt: {exc!r}")
        if bericht is not None:
            print_flag("Teruggevonden bericht", bericht)
        else:
            print("[-] Geen enkele aanval (Wiener / Fermat / Pollard rho / kleine-e-wortel / "
                  "blinding) is geslaagd.")
            print("    Als dit een 'Blind oracle'-achtige oefening is: zet oracle.py in dezelfde")
            print("    map als challenge.json zodat dit script decrypt() kan aanroepen.")
        return

    print("[-] RSA herkend, maar het JSON-patroon komt niet overeen met een bekende oefening.")


# ======================================================================
# ElGamal-aanvallen
# ======================================================================

def elgamal_nonce_reuse_attack(p, g, y, m_known: bytes, c1_known, c2_known,
                                c1_flag, c2_flag, max_delta=1_000_000):
    """Combineert '04_elgamal_nonce_reuse' (zelfde nonce) en
    '06_elgamal_counter_nonce' (teller-nonce, klein verschil) in één aanval:
    als c1_known == c1_flag is delta gewoon 0, anders zoeken we het kleine
    verschil delta met brute force."""
    m_known_int = int.from_bytes(m_known, "big")

    if c1_known == c1_flag:
        print("[+] C1 is identiek voor beide berichten -> nonce k is exact hergebruikt (delta = 0)")
        delta = 0
    else:
        print("[*] C1 verschilt -> zoek klein verschil tussen de nonces (teller-nonce)...")
        ratio = (c1_flag * pow(c1_known, -1, p)) % p
        delta = None
        cur = 1
        for i in range(max_delta):
            if cur == ratio:
                delta = i
                break
            cur = cur * g % p
        assert delta is not None, f"geen klein verschil gevonden binnen {max_delta} pogingen"
        print(f"[+] k_flag - k_known = {delta}")

    y_tot_k_known = (c2_known * pow(m_known_int, -1, p)) % p
    y_tot_k_flag = (y_tot_k_known * pow(y, delta, p)) % p if delta else y_tot_k_known
    m_flag_int = (c2_flag * pow(y_tot_k_flag, -1, p)) % p
    return int_to_bytes(m_flag_int)


def elgamal_weak_group_attack(p, g, y):
    """ElGamal met een VEEL te kleine groep: x rechtstreeks via BSGS."""
    print("[*] Patroon herkend: geen nonce-hergebruik gegeven -> zwakke (te kleine) groep, BSGS.")
    order = p - 1
    x = bsgs(g, y, p, order)
    assert x is not None and pow(g, x, p) == y, "BSGS vond geen geldige private key x"
    print(f"[+] private key x = {x}")
    return x


def elgamal_pohlig_hellman_attack(p, g, y):
    """ElGamal waarbij p-1 volledig "smooth" is (enkel kleine priemfactoren):
    los de discrete log op in elke kleine subgroep en combineer via CRT
    (Pohlig-Hellman), zie 'Smooth operator'."""
    print("[*] Factoriseer p - 1 ...")
    fac = factorint(p - 1)
    print("[+] p - 1 = " + " * ".join(f"{f}^{m}" if m > 1 else str(f) for f, m in fac.items()))

    residues, moduli = [], []
    for f, mult in fac.items():
        if mult != 1:
            print(f"[-] factor {f} komt met multipliciteit {mult} voor; Pohlig-Hellman in deze "
                  f"eenvoudige vorm verwacht multipliciteit 1 per factor - sla deze factor over.")
            continue
        h = pow(g, (p - 1) // f, p)
        t = pow(y, (p - 1) // f, p)
        xi = bsgs(h, t, p, f)
        if xi is None:
            print(f"[-] kon discrete log mod {f} niet oplossen, sla over.")
            continue
        residues.append(xi)
        moduli.append(f)
        print(f"    x = {xi} (mod {f})")

    M = 1
    for mi in moduli:
        M *= mi
    x = sum(r * (M // mi) * pow(M // mi, -1, mi) for r, mi in zip(residues, moduli)) % M
    assert pow(g, x, p) == y, "Pohlig-Hellman/CRT resultaat klopt niet - controleer de JSON"
    print(f"[+] private key x = {x}")
    return x


def solve_elgamal(data, args):
    print("=" * 70)
    print("HERKEND: ElGamal")
    print("=" * 70)

    p, g, y = data["p"], data["g"], data["y"]

    # --- nonce reuse (zelfde of teller-nonce), met gekend bericht ---
    if {"known_plaintext", "cipher_known", "cipher_flag"} <= data.keys():
        print("[*] Patroon herkend: gekend bericht + 2 ciphertexts -> NONCE (HER)GEBRUIK")
        c1_known, c2_known = data["cipher_known"]
        c1_flag, c2_flag = data["cipher_flag"]
        flag = elgamal_nonce_reuse_attack(
            p, g, y,
            data["known_plaintext"].encode(),
            c1_known, c2_known, c1_flag, c2_flag,
            max_delta=args.max_delta,
        )
        print_flag("Teruggevonden bericht", flag)
        return

    # --- rechtstreeks c1/c2 van het doelwit: ofwel zwakke groep ofwel smooth p-1 ---
    if "c1" in data and "c2" in data:
        c1, c2 = data["c1"], data["c2"]
        order = p - 1
        # Heuristiek: is de hele groep klein genoeg voor rechtstreekse BSGS?
        if order.bit_length() <= 70:
            x = elgamal_weak_group_attack(p, g, y)
        else:
            print(f"[*] p - 1 heeft {order.bit_length()} bits: te groot voor rechtstreekse BSGS.")
            x = elgamal_pohlig_hellman_attack(p, g, y)
        m = (c2 * pow(pow(c1, x, p), -1, p)) % p
        print_flag("Flag", int_to_bytes(m))
        return

    # --- encrypted_flag + XOR keystream, geen c1/c2, enkel p,g,y: zwakke groep ---
    if "encrypted_flag" in data:
        print("[*] Patroon herkend: enkel p, g, y + versleutelde vlag -> TE ZWAKKE GROEP (BSGS)")
        order = p - 1
        if order.bit_length() <= 70:
            x = elgamal_weak_group_attack(p, g, y)
        else:
            x = elgamal_pohlig_hellman_attack(p, g, y)
        ct = bytes.fromhex(data["encrypted_flag"])
        ks = keystream(x, len(ct))
        flag = xor_bytes(ct, ks)
        print_flag("Decrypted flag", flag)
        return

    print("[-] ElGamal herkend, maar het JSON-patroon komt niet overeen met een bekende oefening.")


# ======================================================================
# DSA-aanvallen
# ======================================================================

def dsa_H(m: str, q: int) -> int:
    return int.from_bytes(hashlib.sha256(m.encode()).digest(), "big") % q


def dsa_nonce_reuse_attack(p, q, g, y, m1, r1, s1, m2, r2, s2):
    assert r1 == r2, "r1 != r2: GEEN nonce-hergebruik, deze aanval werkt hier niet"
    r = r1
    print("[+] r1 == r2  ->  dezelfde nonce k werd gebruikt voor beide handtekeningen")
    print("[+] sanity check g^q mod p == 1:", pow(g, q, p) == 1)

    h1, h2 = dsa_H(m1, q), dsa_H(m2, q)
    k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q
    x = ((s1 * k - h1) * pow(r, -1, q)) % q

    print(f"[+] k = {k}")
    print(f"[+] x (private key) = {x}")
    print("[+] controle g^x mod p == y:", pow(g, x, p) == y)
    return k, x


def solve_dsa(data, args):
    print("=" * 70)
    print("HERKEND: DSA")
    print("=" * 70)

    p, q, g, y = data["p"], data["q"], data["g"], data["y"]
    sigs = data["signatures"]
    if len(sigs) < 2:
        print("[-] Er zijn minder dan 2 handtekeningen gegeven; nonce-hergebruik kan niet "
              "aangetoond worden.")
        return

    sig1, sig2 = sigs[0], sigs[1]
    if sig1["r"] != sig2["r"]:
        print("[-] r1 != r2: geen nonce-hergebruik gevonden tussen de eerste twee handtekeningen.")
        print("    Dit script herkent enkel het klassieke 'gelijke r' DSA-lek.")
        return

    print("[*] Patroon herkend: twee handtekeningen met dezelfde r -> NONCE (HER)GEBRUIK")
    k, x = dsa_nonce_reuse_attack(
        p, q, g, y,
        sig1["message"], sig1["r"], sig1["s"],
        sig2["message"], sig2["r"], sig2["s"],
    )

    if "encrypted_flag" in data:
        ct = bytes.fromhex(data["encrypted_flag"])
        ks = keystream(x, len(ct))
        flag = xor_bytes(ct, ks)
        print_flag("Teruggevonden bericht", flag)
    else:
        print(f"[+] Private key x teruggevonden: {x}")


# ======================================================================
# Diffie-Hellman (bonus: zelfde discrete-log-aanval als ElGamal/DSA,
# komt niet letterlijk in de vraag voor maar hoort bij dezelfde familie)
# ======================================================================

def solve_diffie_hellman(data, args):
    print("=" * 70)
    print("HERKEND: Diffie-Hellman (zwakke/kleine groep)")
    print("=" * 70)
    p, g = data["p"], data["g"]
    ya, yb = data["Y_alice"], data["Y_bob"]
    order = p - 1
    print(f"[*] p heeft {p.bit_length()} bits -> BSGS op X_alice")
    xa = bsgs(g, ya, p, order)
    assert xa is not None and pow(g, xa, p) == ya, "BSGS vond geen geldige exponent"
    print(f"[+] X_alice = {xa}")
    K = pow(yb, xa, p)
    print(f"[+] gedeelde sleutel K = {K}")
    if "encrypted_flag" in data:
        ct = bytes.fromhex(data["encrypted_flag"])
        flag = xor_bytes(ct, keystream(K, len(ct)))
        print_flag("Decrypted flag", flag)


def solve_mitm_dh(data, args):
    print("=" * 70)
    print("HERKEND: Diffie-Hellman man-in-the-middle (Darth kent al zijn eigen sleutels)")
    print("=" * 70)
    p = data["p"]
    ya = data["Y_A (Alice -> Darth)"]
    yb = data["Y_B (Bob -> Darth)"]
    xd1 = data["darth_private_X_D1"]
    xd2 = data["darth_private_X_D2"]
    ca = bytes.fromhex(data["msg_alice_to_bob"])
    cb = bytes.fromhex(data["msg_bob_to_alice"])

    K2 = pow(ya, xd2, p)  # gedeeld met Alice
    K1 = pow(yb, xd1, p)  # gedeeld met Bob
    print(f"[+] K (Darth<->Alice) = {K2}")
    print(f"[+] K (Darth<->Bob)   = {K1}")

    msg1 = xor_bytes(ca, keystream(K2, len(ca)))
    msg2 = xor_bytes(cb, keystream(K1, len(cb)))
    print_flag("Alice -> Bob", msg1)
    print_flag("Bob -> Alice", msg2)


def solve_fake_primes(data, args):
    """'Fake primes' (Miller-Rabin vs Fermat) - geen RSA/ElGamal/DSA-structuur
    (geen n/e/p/g), maar wel een puur-JSON oefening, dus hier meegenomen."""
    print("=" * 70)
    print("HERKEND: priemgetallen-filter (Miller-Rabin vs Fermat, 'Fake primes')")
    print("=" * 70)
    cands = data["candidates"]
    ct = bytes.fromhex(data["encrypted_flag"])

    priem = sorted(x for x in cands if miller_rabin(x))
    fermat_ok = [x for x in cands if fermat_test(x)]
    print(f"[+] Miller-Rabin: {len(priem)} echte priemgetallen")
    print(f"[+] Fermat laat er {len(fermat_ok)} door "
          f"(dus {len(fermat_ok) - len(priem)} Carmichael-achtige valse positieven)")

    key = ",".join(str(x) for x in priem)
    ks = keystream(key, len(ct))
    flag = xor_bytes(ct, ks)
    print_flag("Flag", flag)


# ======================================================================
# Herkenning / dispatcher
# ======================================================================

def detect_and_solve(data, args):
    keys = set(data.keys())

    # --- KDC-replay oefening ('Old keys new doors') ---
    if "Ks_old" in data or "recorded_ticket_step3" in data:
        print("=" * 70)
        print("HERKEND: KDC-replay aanval ('Old keys new doors')")
        print("=" * 70)
        server = load_sibling_module(args.challenge_json, "server.py")
        if server is not None and hasattr(server, "step3") and hasattr(server, "step5"):
            print("[*] server.py gevonden naast de JSON -> replay-aanval met gelekte Ks_old...")
            result = kdc_replay_attack(
                data["Ks_old"], data["recorded_ticket_step3"], server.step3, server.step5
            )
            print(f"[+] Resultaat van server.step5(): {result}")
        else:
            print("[-] Geen server.py gevonden naast deze JSON (nodig voor step3()/step5()).")
            print("    Zet server.py in dezelfde map als challenge.json om dit op te lossen.")
        return

    # --- DSA: heeft p, q, g, y en een lijst handtekeningen ---
    if {"p", "q", "g", "y", "signatures"} <= keys:
        solve_dsa(data, args)
        return

    # --- ElGamal: heeft p, g, y, maar GEEN q (dat onderscheidt het van DSA) ---
    if {"p", "g", "y"} <= keys:
        solve_elgamal(data, args)
        return

    # --- Diffie-Hellman man-in-the-middle (specifiek JSON-patroon) ---
    if "darth_private_X_D1" in data:
        solve_mitm_dh(data, args)
        return

    # --- Diffie-Hellman (kleine groep, geen ElGamal y) ---
    if {"p", "g", "Y_alice", "Y_bob"} <= keys:
        solve_diffie_hellman(data, args)
        return

    # --- Fake primes (geen n/e/p/g, wel candidates-lijst) ---
    if "candidates" in data:
        solve_fake_primes(data, args)
        return

    # --- RSA: heeft n en e (of n en e1/e2) ---
    if "n" in keys and ("e" in keys or {"e1", "e2"} <= keys):
        solve_rsa(data, args)
        return

    print("[-] Kon het cryptosysteem niet herkennen in deze JSON.")
    print(f"    Gevonden velden: {sorted(keys)}")
    print("    Mogelijk is dit een oefening die een levende server/oracle nodig heeft")
    print("    (zoals 'Blind oracle' of 'Forged receipt') - die zijn hier bewust genegeerd.")


# ======================================================================
# main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Automatische kraker voor RSA/ElGamal/DSA-oefeningen uit een challenge JSON."
    )
    parser.add_argument(
        "challenge_json", nargs="?", default="challenge.json",
        help="pad naar het challenge-JSON-bestand (default: challenge.json in de huidige map)",
    )
    parser.add_argument(
        "--max-delta", type=int, default=1_000_000,
        help="maximum aantal brute-force stappen voor de teller-nonce / discrete log zoektochten "
             "(default: 1.000.000)",
    )
    parser.add_argument(
        "--inspect", metavar="BESTANDSNAAM", nargs="?", const="server.py",
        help="in plaats van te kraken: toon enkel de functies in een naastliggend "
             "oracle.py/server.py (standaard: server.py), handig bij een onbekend "
             "protocol met bv. een step6() of iets anders onverwachts.",
    )
    args = parser.parse_args()

    if args.inspect:
        inspect_sibling_module(args.challenge_json, args.inspect)
        return

    try:
        with open(args.challenge_json, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[-] Bestand niet gevonden: {args.challenge_json}")
        print("    Zet het script in dezelfde map als challenge.json, of geef het pad mee:")
        print("    python3 crypto_solver.py pad/naar/jouw_bestand.json")
        sys.exit(1)

    print(f"[*] JSON ingelezen: {args.challenge_json}")
    print(f"[*] Velden: {sorted(data.keys())}")
    print()

    try:
        detect_and_solve(data, args)
    except AssertionError as exc:
        print(f"[-] Aanval mislukt: {exc}")
    except Exception as exc:
        print(f"[-] Onverwachte fout tijdens het kraken: {exc!r}")


if __name__ == "__main__":
    main()
