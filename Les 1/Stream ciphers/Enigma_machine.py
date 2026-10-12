import string

ALFABET = string.ascii_uppercase

ROTOR1 = "MACHINEBDFGJKLOPQRSTUVWXYZ"
ROTOR2 = "ORBITACDEFGHJKLMNPQSUVWXYZ"
ROTOR3 = "CIPHERABDFGJKLMNOQSTUVWXYZ"


def draai(rotor):
    """Eerste letter gaat naar achteren: 'MACH...' -> 'ACH...M'."""
    return rotor[1:] + rotor[0]


def verwerk(tekst, decode=False, start=(0, 0, 0), verbose=False):
    r1, r2, r3 = ROTOR1, ROTOR2, ROTOR3

    # Beginstanden: draai elke rotor start[i] keer
    for _ in range(start[0]): r1 = draai(r1)
    for _ in range(start[1]): r2 = draai(r2)
    for _ in range(start[2]): r3 = draai(r3)

    # Tellers: hoeveel stappen zette elke rotor sinds zijn beginstand
    t1, t2 = start[0] % 26, start[1] % 26

    resultaat = []
    for teken in tekst:
        if teken.upper() not in ALFABET:
            resultaat.append(teken)      # spatie, {, }, - ... gaan ongewijzigd door
            continue

        # Rotor 1 draait altijd; overdracht naar rotor 2 en 3
        r1 = draai(r1)
        t1 += 1
        if t1 % 26 == 0:
            r2 = draai(r2)
            t2 += 1
            if t2 % 26 == 0:
                r3 = draai(r3)

        i = ALFABET.index(teken.upper())

        if not decode:
            a = ALFABET.index(r1[i])     # rotor 1
            b = ALFABET.index(r2[a])     # rotor 2
            uit = r3[b]                  # rotor 3
        else:
            # Omgekeerde route: eerst rotor 3, dan 2, dan 1
            b = r3.index(ALFABET[i])
            a = r2.index(ALFABET[b])
            uit = ALFABET[r1.index(ALFABET[a])]

        if verbose:
            print(f"{teken} ({i}) -> {uit}   rotor1={r1}")

        resultaat.append(uit if teken.isupper() or decode else uit.lower())

    return "".join(resultaat)

if __name__ == '__main__':
    print(verwerk("HKV{BSBU-B-SJYZNNB-DNFW-IXH-YTA-RPL-RTXOLWFQ}", decode=True, start=(0, 0, 0), verbose=False))