# https://docs.xanhacks.xyz/crypto/rsa/08-hastad-broadcast-attack/

# n1 = 55 (5*11), n2 = 51 (3*17), n3 = 91 (7*13)   -> pairwise coprime
# M = 8
# M^3 = 512

# C1 = M^3 mod n1 = 512 mod 55 = 17
# C2 = M^3 mod n2 = 512 mod 51 = 2
# C3 = M^3 mod n3 = 512 mod 91 = 57

# N   = n1*n2*n3 = 55*51*91 = 255255
# N1  = n2*n3 = 51*91 = 4641
# N2  = n1*n3 = 55*91 = 5005
# N3  = n1*n2 = 55*51 = 2805

# y1 = N1^-1 mod n1 = 4641^-1 mod 55 = 21^-1 mod 55 = 21   (21*21 = 441 = 8*55 + 1)
# y2 = N2^-1 mod n2 = 5005^-1 mod 51 =  7^-1 mod 51 = 22   (7*22  = 154 = 3*51 + 1)
# y3 = N3^-1 mod n3 = 2805^-1 mod 91 = 75^-1 mod 91 = 17   (75*17 = 1275 = 14*91 + 1)

# X = C1*N1*y1 + C2*N2*y2 + C3*N3*y3  mod N
#   = 17*4641*21 + 2*5005*22 + 57*2805*17  mod 255255
#   = 1656837 + 220220 + 2718045 mod 255255
#   = 4595102 mod 255255
#   = 512

# M = cube root of 512 = 8   (no modular reduction needed since M^3 < N)

# kijk op number theory slides (homework)

import re
t = open('ciphertexts-2.txt').read()
k = open('public_keys-2.txt').read()
c = [int(x) for x in re.findall(r'c\d = (\d+)', t)]
n = [int(x) for x in re.findall(r'n = (\d+)', k)]

def icbrt(x):                      # integer cube root by binary search
    lo, hi = 0, 1 << (x.bit_length() // 3 + 2)
    while lo < hi:
        m = (lo + hi) // 2
        if m**3 < x: lo = m + 1
        else: hi = m
    return lo

# CRT: combine the three congruences M^3 ≡ c_i (mod n_i)
N = n[0] * n[1] * n[2]
X = sum(ci * (N // ni) * pow(N // ni, -1, ni) for ci, ni in zip(c, n)) % N

M = icbrt(X)
assert M**3 == X                   # exact cube, so the attack worked
print(M.to_bytes((M.bit_length() + 7) // 8, 'big'))