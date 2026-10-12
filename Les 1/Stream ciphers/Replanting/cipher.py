"""
Encryption module.

This module implements a custom stream cipher.
"""

# LCG parameters
A = 1103515245
C = 12345
M = 2**31


def next_state(state):
    """Generate the next PRNG state."""
    return (A * state + C) % M


def generate_keystream(seed, length):
    """Generate a pseudorandom keystream."""
    state = seed
    keystream = bytearray()

    for _ in range(length):
        state = next_state(state)
        keystream.append((state >> 16) & 0xff)

    return bytes(keystream)


def encrypt(plaintext, seed):
    """Encrypt plaintext using XOR."""
    keystream = generate_keystream(seed, len(plaintext))
    return bytes(
        p ^ k for p, k in zip(plaintext, keystream)
    )


def decrypt(ciphertext, seed):
    """Decrypt ciphertext using XOR."""
    return encrypt(ciphertext, seed)

def recover_seed(plaintext, ciphertext):
    ks = bytes(p ^ c for p, c in zip(plaintext, ciphertext))
    kandidaten = []
    for low in range(2**16):
        s = (ks[0] << 16) | low           # bits 0..23 van s1
        ok = True
        for k in ks[1:]:
            s = (A * s + C) % 2**24       # enkel de lage 24 bits tellen
            if (s >> 16) != k:
                ok = False
                break
        if ok:
            kandidaten.append((ks[0] << 16) | low)
    ainv = pow(A, -1, 2**24)
    return [((s1 - C) * ainv) % 2**24 for s1 in kandidaten]

def recover_seed_v1(plaintext, ciphertext):
    ks = bytes(p ^ c for p, c in zip(plaintext, ciphertext))
    kandidaten = []
    for seed in range(2**24):
        if generate_keystream(seed, 4) == ks[:4]:      # snelle voorfilter
            if generate_keystream(seed, len(ks)) == ks: # volledige check
                kandidaten.append(seed)
    return kandidaten
if __name__ == '__main__':
    pt = b"STATUS: SERVER ONLINE"
    ct = bytes.fromhex("22135cc0b9daa9e717f98a998e6ee5e92655e1a88f")
    cp = bytes.fromhex("12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b01d833d628a941b82fb65176b4ed3c3f64")

    seeds = recover_seed(pt, ct)
    print(seeds)  # [3430008]
    print(decrypt(ct, seeds[0]))  # b'STATUS: SERVER ONLINE'

    print(decrypt(cp, seeds[0]))
    print("stinky")
    print(recover_seed_v1(pt, ct))
