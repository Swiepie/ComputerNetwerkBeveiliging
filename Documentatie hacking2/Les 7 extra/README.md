# Les 7 – extra oefeningen (Computer and Network Security)

Zelfde opzet als Les 5 en 6: elke opgave heeft een eigen map en de flag heeft altijd het formaat `cns{...}`.

- `opgaven/`: enkel de challenge-bestanden (en `oracle.py` / `server.py` waar je een "server" moet aanspreken). Niet in `_d`, `_Kb`, `_FLAG` en dergelijke kijken; behandel die bestanden als een server op afstand.
- `oplossingen/`: dezelfde map, plus mijn `test.py` met uitleg in commentaar. Draai met `python3 test.py` in de map. Alle negen geven de flag.

## Wat zat er al in je oefeningen en wat is nieuw?

| Onderwerp uit de cursus | Eerder getest (Les 5/6) | Nu getest |
|---|---|---|
| RSA gemeenschappelijke modulus | Free keys | |
| RSA kleine d (Wiener) | Sports car desire | |
| RSA kleine e + CRT (Hastad) | group chat, better group chat | |
| RSA factoriseren (Pollard rho) | Shifting sand | |
| ElGamal nonce-hergebruik | Assymetric nonsense, Fresh (k2 = k1 + 1) | |
| DSA nonce-hergebruik | Double entry | |
| RSA: phi(n) bepalen is gelijk aan factoriseren (slide 51) | | 1 Spilled totient |
| RSA chosen-ciphertext aanval (slide 56) | | 2 Blind oracle |
| ElGamal: q-1 moet een grote priemfactor hebben (slide 68) | | 3 Smooth operator |
| Diffie-Hellman: veiligheid = discrete log (Part 5, slide 24) | | 4 Small Diffie |
| Diffie-Hellman man-in-the-middle (Part 5, slide 25) | | 5 Darth in the middle |
| RSA multiplicatieve eigenschap bij handtekeningen (slide 56, 77) | | 6 Forged receipt |
| RSA met CRT-versnelling (slides 40 tot 43) | | 7 Glitch |
| Miller-Rabin en Fermat (Number Theory slides 8 en 10) | | 8 Fake primes |
| KDC-replay met een gelekte oude sessiesleutel (Part 5, slide 52) | | 9 Old keys new doors |

### Nog niet getest en ook niet als code: de handreken-oefeningen onderaan

timing-aanval en blinding, DSA-verificatie, uitgebreid Euclides, Euler/Fermat-reductie, CRT met de formule van de slides, primitieve wortels, Miller-Rabin met de hand, RSA-CRT-ontcijfering, ElGamal met de hand, het aantal sleutels bij KDC en Kerberos-realms, certificaatketens (X.509) en Kerberos v4 en v5.

## De negen challenges

| # | Map | Idee (niet lezen als je eerst zelf wilt proberen) | Hint |
|---|---|---|---|
| 1 | Spilled totient | Je krijgt n, e, c en ook phi(n) | phi(n) = n - (p+q) + 1. Welke vergelijking hebben p en q als nulpunten? |
| 2 | Blind oracle | Een oracle ontcijfert alles behalve jouw c | Hoe verander je c zodat het een andere ciphertext wordt maar de plaintext voorspelbaar blijft? |
| 3 | Smooth operator | ElGamal met een bijzondere p | Factoriseer p - 1. Welke stelling combineert kleine subgroepen? |
| 4 | Small Diffie | DH met een kleine priem, sleutel versleutelt de flag | Hoeveel stappen kost baby-step giant-step bij 40 bit? |
| 5 | Darth in the middle | Jij bent de aanvaller met beide privésleutels | Welke twee sleutels rekent Darth uit? |
| 6 | Forged receipt | Je moet een handtekening vervalsen die de server niet wil zetten | Zoek twee berichten waarvan het product het doelbericht is |
| 7 | Glitch | Eén foute CRT-handtekening | Voor welke priemgetallen klopt s^e = m nog wel? |
| 8 | Fake primes | Welke getallen zijn echt priem? | Waarom vindt Fermat er meer dan Miller-Rabin? |
| 9 | Old keys new doors | Replay van stap 3 met een oude Ks | Waarom helpt stap 4 en 5 niet als Ks gelekt is? |

---

# Handreken-oefeningen

Werk alles uit zoals in de slides (met tussenstappen). Oplossingen staan eronder.

**H1. Uitgebreid Euclides.** Bereken 37^-1 mod 120 met het schema van slide 7 (r, q, w).

**H2. Fermat en Euler.** (a) Bereken 7^222 mod 13. (b) Bereken 3^100 mod 35 via phi(35).

**H3. CRT.** Los x op: x ≡ 1 (mod 4), x ≡ 2 (mod 9), x ≡ 3 (mod 11), met M_i en c_i uit de formule van slide 12.

**H4. Diffie-Hellman en discrete log.** p = 23, g = 5, X_A = 6, X_B = 15. (a) Bereken Y_A, Y_B en K aan beide kanten. (b) Voor p = 11: geef de tabel van dlog_{2,11} en alle primitieve wortels van 11.

**H5. Miller-Rabin met de hand.** (a) n = 561, a = 2. (b) n = 221, a = 174 en a = 137. Wat zeggen de resultaten?

**H6. RSA met CRT-ontcijfering.** p = 17, q = 23, e = 5. Bereken n, phi, d. Versleutel M = 42. Ontcijfer C met V_p, V_q en de CRT-formule.

**H7. Blinding tegen timing-aanvallen.** Zelfde sleutel als H6, C = 264, r = 3. Toon dat (C·r^e)^d · r^-1 = M, zonder dat de decryptor C zelf ziet.

**H8. ElGamal.** q = 19, alpha = 2, X_A = 5. (a) Y_A. (b) Versleutel M = 17 met k = 6. (c) Ontcijfer. (d) Zelfde k opnieuw voor een tweede bericht, C2' = 7: bereken M2 als M1 = 17 bekend is.

**H9. DSA met de hand.** p = 23, q = 11, g = 4, x = 3, H(M) = 7, k = 5. Bereken y, (r, s) en verifieer. Daarna: tweede bericht H(M') = 4 met dezelfde k. Haal k en x uit de twee handtekeningen.

**H10. Sleutels tellen.** N = 50 hosts. Hoeveel sessiesleutels maximaal, hoeveel masterkeys decentraal, hoeveel met een KDC? En N = 12 Kerberos-realms in v4 en v5 (slide 59, 62).

**H11. Certificaatketens.** Gebruik de hiërarchie van slide 40. Geef het certificatiepad dat B nodig heeft om de sleutel van C te krijgen, en wat C moet vertrouwen. Wat gebeurt er als W gecompromitteerd wordt (CRL)?

**H12. Kerberos.** (a) Maximale ticketlevensduur in v4 met een 8-bit veld in eenheden van 5 minuten. (b) Waarom is in v4 een authenticator eenmalig en een ticket herbruikbaar? (c) Noem twee redenen waarom v5 sub-session keys en pre-authenticatie toevoegt.

---

# Oplossingen

**H1.** Init: r_-1 = 120, w_-1 = 0; r_0 = 37, w_0 = 1.
- i = 1: q = 120 div 37 = 3; r = 120 mod 37 = 9; w = 0 - 3·1 = -3
- i = 2: q = 37 div 9 = 4; r = 37 mod 9 = 1; w = 1 - 4·(-3) = 13
- r = 1, dus 37^-1 = 13. Controle: 37·13 = 481 = 4·120 + 1.

**H2.** (a) 13 is priem en 7 is geen veelvoud van 13, dus 7^12 ≡ 1. 222 = 18·12 + 6, dus 7^222 ≡ 7^6. 7^2 = 49 ≡ 10; 7^3 ≡ 70 ≡ 5; 7^6 ≡ 25 ≡ **12**.
(b) phi(35) = 4·6 = 24. 100 = 4·24 + 4, dus 3^100 ≡ 3^4 = 81 = 2·35 + 11, dus **11**.

**H3.** M = 4·9·11 = 396.
- m1 = 4: M1 = 99, 99 mod 4 = 3, 3^-1 = 3, c1 = 99·3 = 297
- m2 = 9: M2 = 44, 44 mod 9 = 8, 8^-1 = 8, c2 = 44·8 = 352
- m3 = 11: M3 = 36, 36 mod 11 = 3, 3^-1 = 4, c3 = 36·4 = 144
- x = 1·297 + 2·352 + 3·144 = 297 + 704 + 432 = 1433 mod 396 = **245**. Controle: 245 mod 4 = 1, mod 9 = 2, mod 11 = 3.

**H4.** (a) Y_A = 5^6 mod 23 = 8; Y_B = 5^15 mod 23 = 19; K = 19^6 mod 23 = 8^15 mod 23 = **2**.
(b) Machten van 2 mod 11 voor i = 1 tot 10: 2, 4, 8, 5, 10, 9, 7, 3, 6, 1. Dus dlog(2)=1, dlog(4)=2, dlog(8)=3, dlog(5)=4, dlog(10)=5, dlog(9)=6, dlog(7)=7, dlog(3)=8, dlog(6)=9, dlog(1)=10 (of 0). Primitieve wortels van 11: **2, 6, 7, 8** (phi(11) = 4 van de 10 elementen).

**H5.** (a) 560 = 2^4·35. 2^35 mod 561 = 263; 263² ≡ 166; 166² ≡ 67; 67² ≡ 1. Nooit n-1 = 560 bij de eerste stap of een kwadraat ervan, en 1 komt van 67 ≠ ±1 (een niet-triviale wortel van 1). Dus **561 is samengesteld**, hoewel 2^560 ≡ 1 (mod 561): een Carmichael-getal.
(b) 220 = 4·55, k = 2, q = 55. a = 174: 174^55 ≡ 47, 47² ≡ 220 = n-1, dus "mogelijk priem" voor deze a (een strong liar, 221 = 13·17 is toch samengesteld). a = 137: 137^55 ≡ 188, 188² ≡ 205, nooit 1 of n-1, dus **samengesteld**. Daarom herhaal je met t verschillende a's: kans op een fout is hoogstens (1/4)^t.

**H6.** n = 391, phi = 16·22 = 352, d = 5^-1 mod 352 = 141 (5·141 = 705 = 2·352 + 1). C = 42^5 mod 391 = 264.
d mod 16 = 13, d mod 22 = 9. V_p = 264^13 mod 17 = 8, V_q = 264^9 mod 23 = 19.
X_p = q·(q^-1 mod p) = 23·3 = 69, X_q = p·(p^-1 mod q) = 17·19 = 323.
M = (8·69 + 19·323) mod 391 = 6689 mod 391 = **42**.

**H7.** r^e = 3^5 = 243. X = 264·243 = 64152 ≡ 28 (mod 391). Y = 28^141 mod 391 = 126. r^-1 = 261 (3·261 = 783 = 2·391 + 1). M = 126·261 mod 391 = **42**. De decryptor ziet alleen X = 28, niet C = 264, dus de looptijd lekt niets over C.

**H8.** (a) Y_A = 2^5 mod 19 = 13. (b) C1 = 2^6 mod 19 = 7, K = 13^6 mod 19 = 11, C2 = 11·17 mod 19 = 16. (c) K = C1^5 = 7^5 mod 19 = 11, K^-1 = 7, M = 16·7 = 112 mod 19 = **17**. (d) K = C2 · M1^-1 = 16 · 9 = 144 mod 19 = 11 (17^-1 = 9). M2 = C2' · K^-1 = 7 · 7 = 49 mod 19 = **11**.

**H9.** y = 4^3 mod 23 = 18. r = (4^5 mod 23) mod 11 = 12 mod 11 = 1. s = 5^-1 (7 + 3·1) mod 11 = 9·10 = 90 mod 11 = 2. Verificatie: w = 2^-1 = 6, u1 = 7·6 mod 11 = 9, u2 = 1·6 = 6, v = (4^9 · 18^6 mod 23) mod 11 = 1 = r, dus **geldig**.
Tweede bericht: s' = 9·(4 + 3) = 63 mod 11 = 8, zelfde r = 1 (zelfde k). Dan k = (H - H')/(s - s') = 3/(2 - 8) = 3/5 = 3·9 = 27 mod 11 = **5**, en x = (s·k - H)/r = (10 - 7)/1 = **3**.

**H10.** Sessiesleutels: N(N-1)/2 = 50·49/2 = **1225**. Decentraal: ook **1225** masterkeys. KDC: **50**. Kerberos-realms: v4 N(N-1)/2 = 12·11/2 = **66** relaties; v5 minder, via een hiërarchie die niet kwadratisch groeit.

**H11.** B vertrouwt Z en wil de sleutel van C verifiëren. Pad (slide 40, omgekeerd): **Z<<Y>> Y<<V>> V<<W>> W<<X>> X<<C>>**. B moet alleen Z vertrouwen. Wordt W gecompromitteerd, dan zet de CA die W certificeerde (hier V en X) de certificaten V<<W>> en X<<W>> op hun CRL (serienummer plus datum), zodat de keten voorbij W ongeldig wordt, ook als de certificaten nog niet verlopen zijn.

**H12.** (a) 2^8 · 5 = 1280 minuten (volgens de slides, iets meer dan 21 uur). (b) De authenticator bevat een timestamp en heeft een zeer korte levensduur; hij bewijst identiteit nu. Het ticket bewijst niets, het verdeelt enkel sleutels veilig, dus kan het herbruikt worden. (c) Sub-session keys: elke verbinding krijgt een eigen sleutel zodat replay uit een oude sessie niet werkt. Pre-authenticatie: een aanvaller kan het AS-bericht niet meer zomaar opvangen en offline wachtwoorden proberen, al blokkeert het dat niet volledig.
